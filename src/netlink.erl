%%%---- BEGIN COPYRIGHT -------------------------------------------------------
%%%
%%% Copyright (C) 2012 Feuerlabs, Inc. All rights reserved.
%%%
%%% This Source Code Form is subject to the terms of the Mozilla Public
%%% License, v. 2.0. If a copy of the MPL was not distributed with this
%%% file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%%
%%%---- END COPYRIGHT ---------------------------------------------------------
%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @doc
%%%    Netlink state monitor
%%% @end
%%% Created : 11 Jun 2012 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(netlink).

-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1]).
-export([start/0, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).
-export([i/0, i/1]).
-export([subscribe/0,subscribe/1,subscribe/2,subscribe/3]).
-export([unsubscribe/1]).
-export([invalidate/2]).
-export([get_root/2, get_match/3, get/4]).
-export([getiflist/0]).
-export([getlinkattr/1, getlinkattr/2]).
-export([getaddrattr/1, getaddrattr/2]).

%% -include("log.hrl").
-include("netlink.hrl").
-include("netl_codec.hrl").

-define(error(F, A), io:format((F)++"\n",(A))).
%% -define(debug(F, A), io:format((F)++"\n",(A))).
-define(debug(F, A), ok).
-define(warning(F, A), io:format((F)++"\n",(A))).
%% -define(warning(F, A), ok).
%% -define(info(F, A), io:format((F)++"\n",(A))).
-define(info(F, A), ok).

-ifdef(OTP_RELEASE). %% this implies 21 or higher
-define(EXCEPTION(Class, Reason, Stacktrace), Class:Reason:Stacktrace).
-define(GET_STACK(Stacktrace), Stacktrace).
-else.
-define(EXCEPTION(Class, Reason, _), Class:Reason).
-define(GET_STACK(_), erlang:get_stacktrace()).
-endif.

-define(SERVER, ?MODULE). 

-type uint8_t() :: 0..16#ff.
-type uint16_t() :: 0..16#ffff.

-type ipv4_addr() :: {uint8_t(),uint8_t(),uint8_t(),uint8_t()}.
-type ipv6_addr() :: {uint16_t(),uint16_t(),uint16_t(),uint16_t(),
		      uint16_t(),uint16_t(),uint16_t(),uint16_t()}.

-type if_addr() :: ipv4_addr() | ipv6_addr().

-type if_name() :: string().

-type if_index() :: non_neg_integer().

-type if_match() :: if_index()|if_name()|if_addr(). %% |"*"

-type match_op_t() :: '==' | '=:=' | '<' | '=<' | '>=' | '/=' | '=/='.

-type attr_name() :: atom() | integer().

-type match_t() ::  Field::attr_name() |
		    {Field::attr_name(),Value::term()} |
		    {Op::match_op_t(),Field::attr_name(),Value::term()}.

-type type_match_t() :: 'any'|'addr'|'link'.

-type sub_match_t() :: type_match_t() | match_t() | [match_t()] |
		       {type_match_t(),match_t()} |
		       [{type_match_t(),match_t()}].
		       
-type attr_t() :: #{ attr_name() => term() }.

-define(ANY, any).
-define(LINK, link).
-define(ADDR, addr).

-record(link, 
	{
	 name     :: if_name(),           %% interface name (unique)
	 index    :: if_index(),          %% interface index (unique)
	 addr     :: #{ if_addr() => attr_t() },
	 attr     :: attr_t() %% attributes
	}).

-record(sub,
	{
	 ref  :: reference(),         %% ref and monitor
	 pid  :: pid(),               %% subscriber
	 name :: string(),            %% name
	 match :: sub_match_t()       %% event match
	}).

-define(MIN_RCVBUF,  (128*1024)).
-define(MIN_SNDBUF,  (32*1024)).

-define(REQUEST_TMO, 2000).

-record(request,
	{
	 tmr,      %% timer reference
	 call,     %% call request
	 from,     %% caller
	 reply=ok, %% reply to send when done
	 seq=0     %% sequence to expect in reply
	}).

-record(state, 
	{
	 port,
	 ifnames = #{} :: #{ string() => if_index() },
	 links = #{} :: #{ if_index() => #link{} },
	 subs = #{} :: #{ reference() => #sub{} },
	 request         :: undefined | #request{},
	 request_queue = [] :: [#request{}],
	 o_seq = 0,
	 i_seq = 0,
	 ospid
        }).

%%%===================================================================
%%% API
%%%===================================================================

start() ->
    application:start(netlink).

i() ->
    i("*").

i(Interface) ->
    Verbose = false,
    Ifs = getlinkattr(Interface, index),
    lists:foreach(
      fun({index,I}) ->
	      LinkAttrs = getlinkattr(I),
	      AddrAttrs = getaddrattr(I),
	      Addr = [format_addr_attrs(AttrList, Verbose) ||
			 AttrList <- AddrAttrs],
	      lists:foreach(
		fun(Attrs) ->
			io:format("link {~s~s}\n",
				  [Addr,format_link_attrs(Attrs, Verbose)])
		end, LinkAttrs)
      end, Ifs).
		 

stop() ->
    gen_server:call(?SERVER, stop).

-spec getiflist() -> {ok,[string()]}.

getiflist() ->
    {ok,[Name || {ifname,Name} <- getlinkattr("*", ifname)]}.

%% return link attributes from interface index or interface name

-spec getlinkattr(Interface::if_match()) -> [[{attr_name(),term()}]].

getlinkattr(Interface) ->
    getifattr(Interface, link, ?ANY).

-spec getlinkattr(Interface::if_match(), Fields::match_t()) ->
	  [[{attr_name(),term()}]].

getlinkattr(Interface, Fields) ->
    getifattr(Interface, link, Fields).

-spec getaddrattr(Interface::if_match()) -> [[{attr_name(),term()}]].

getaddrattr(Interface) ->
    getifattr(Interface,addr,?ANY).

-spec getaddrattr(Interface::if_match(), Fields::match_t()) ->
	  [[{attr_name(),term()}]].

getaddrattr(Interface,Fields) ->
    getifattr(Interface,addr,Fields).

getifattr(Interface,Type,Fields) ->
    gen_server:call(?SERVER, {getifattr,Type,Interface,Fields}). 

%% @doc
%%   Subscribe to interface changes, notifications will be
%%   sent in {netlink,reference(),if_name(),if_field(),OldValue,NewValue}
%% @end

-spec subscribe() ->
	  {ok,reference()}.

subscribe() ->
    subscribe("*",all,[]).

-spec subscribe(Name::string()) -> 
	  {ok,reference()}.

subscribe(Name) ->
    subscribe(Name,all,[]).

-spec subscribe(Name::string(),Match::sub_match_t()) ->
	  {ok,reference()}.

subscribe(Name,Match) ->
    subscribe(Name,Match,[]).

-spec subscribe(Name::string(),Match::sub_match_t(),Otions::[flush]) ->
	  {ok,reference()}.

subscribe(Name,Match,Options) ->
    gen_server:call(?SERVER, {subscribe,self(),Name,Match,Options}).

unsubscribe(Ref) ->
    gen_server:call(?SERVER, {unsubscribe,Ref}).

%% clear all attributes for interface Name - to generate new events
%% should be synced somehow.

-spec invalidate(Intetface::if_match(), Fields::[attr_name()]) ->
    ok.

invalidate(Interface,Fields) ->
    gen_server:call(?SERVER, {invalidate,Interface,Fields}).


get_root(What,Fam) ->
    get(What,Fam,[root,match,request],[]).

get_match(What,Fam,GetAttrs) ->
    get(What,Fam,[match,request],GetAttrs).

get(What,Fam,GetFlags,GetAttrs) ->
    gen_server:call(?SERVER, {get,What,Fam,GetFlags,GetAttrs}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    start_link([]).
start_link(Opts) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Opts], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Opts]) ->
    OsPid = list_to_integer(os:getpid()),
    I_Seq = O_Seq = 1234, %% element(2,now()),
    State = #state{ ospid = OsPid, 
		    o_seq = O_Seq, 
		    i_seq = I_Seq },

    case os:type() of
	{unix, linux} ->
	    init_drv(Opts, State);
	_ ->
	    {ok, State}
    end.

init_drv(Opts, State) ->
    Port = netlink_drv:open(?NETLINK_ROUTE),

    netlink_drv:debug(Port, proplists:get_value(debug,Opts,none)),

    {ok,_Rcvbuf} = update_rcvbuf(Port, ?MIN_RCVBUF),
    {ok,_Sndbuf} = update_sndbuf(Port, ?MIN_SNDBUF),

    ?info("Rcvbuf: ~w, Sndbuf: ~w", [_Rcvbuf, _Sndbuf]),

    {ok,_Sizes} = netlink_drv:get_sizeof(Port),
    ?info("Sizes: ~w", [_Sizes]),

    ok = netlink_drv:add_membership(Port, ?RTNLGRP_LINK),
    ok = netlink_drv:add_membership(Port, ?RTNLGRP_IPV4_IFADDR),
    ok = netlink_drv:add_membership(Port, ?RTNLGRP_IPV6_IFADDR),

    netlink_drv:activate(Port),
    %% init sequence to fill the cache
    T0 = erlang:start_timer(200, self(), request_timeout),
    R0 = #request { tmr  = T0, 
		    call = noop, 
		    from = {self(),make_ref()} 
		  },
    R1 = #request { tmr  = {relative, ?REQUEST_TMO},
		    call = {get,link,unspec,
			    [root,match,request],
			    []},
		    from = {self(),make_ref()}
		  },
    R2 = #request { tmr  = {relative, 1000}, 
		    call = noop,
		    from = {self(),make_ref()}
		  },
    R3 = #request { tmr = {relative,?REQUEST_TMO},
		    call = {get,addr,unspec,
			    [root,match,request],
			    []},
		    from = {self(),make_ref()}
		  },
    {ok, State#state{ port=Port,
		      request = R0,
		      request_queue = [R1,R2,R3]
		    }}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------

handle_call({subscribe,Pid,Name,Match,Options}, _From, State) ->
    Mon = erlang:monitor(process, Pid),
    S = #sub { ref=Mon, pid=Pid, name=Name, match=Match },
    Subs = (State#state.subs)#{ Mon => S },
    case proplists:get_bool(flush, Options) of
	false ->
	    {reply, {ok,Mon}, State#state { subs = Subs }};
	true ->
	    maps:fold(
	      fun(_Index, L, _Ai) ->
		      As = maps:to_list(L#link.attr),
		      update_attrs(L#link.name,link,As,#{},[S]),
		      maps:fold(
			fun(_Addr, Attr, _Aj) ->
				As = maps:to_list(Attr),
				update_attrs(L#link.name,addr,As,#{},[S])
			end, ok, L#link.addr)
	      end, ok, State#state.links),
	    {reply, {ok,Mon}, State#state { subs = Subs }}
    end;
handle_call({unsubscribe,Ref}, _From, State) ->
    case maps:take(Ref, State#state.subs) of
	error ->
	    {reply,ok,State};
	{Sub,Subs} ->
	    erlang:demonitor(Sub#sub.ref, [flush]),
	    {reply,ok,State#state { subs=Subs }}
    end;
handle_call({invalidate,Interface,Fields},_From,State) ->
    case match_interface(Interface, State) of
	[] ->
	    {reply, {error, enoent}, State};
	Ls ->
	    Links =
		lists:fold(
		  fun(L, Links) ->
			  Attr = lists:foldl(
				   fun(F,D) when is_atom(F) ->
					   maps:remove(F, D)
				   end, L#link.attr, Fields),
			  L1 = L#link { attr = Attr },
			  Links#{ L#link.index => L1 }
		  end, State#state.links, Ls),
	    {reply, ok, State#state { links = Links }}
    end;

handle_call(Req={get,_What,_Fam,_Flags,_Attrs}, From, State) ->
    ?debug("handle_call: GET: ~p", [Req]),
    State1 = enq_request(Req, From, State),
    State2 = dispatch_command(State1),
    {noreply, State2};

handle_call({getifattr,link,Interface,Match},_From,State) ->
    case match_interface(Interface, State) of
	[] ->
	    {reply, [], State};
	Ls ->
	    {reply, match_link(Ls,Match), State}
    end;
handle_call({getifattr,addr,Interface,Match},_From,State) ->
    case match_interface(Interface, State) of
	[] ->
	    {reply, [], State};
	Ls ->
	    {reply, match_addr(Ls,Match), State}
    end;
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------

handle_info(_Info={nl_data,Port,Data},State) when Port =:= State#state.port ->
    try netlink_codec:decode(Data,[]) of
	MsgList ->
	    %% FIXME: the messages should be delivered one by one from
	    %% the driver so the decoding could simplified.
	    State1 = 
		lists:foldl(
		  fun(Msg,StateI) ->
			  ?debug("handle_info: msg=~p", [Msg]),
			  _Hdr = Msg#nlmsg.hdr,
			  MsgData = Msg#nlmsg.data,
			  handle_nlmsg(MsgData, StateI)
		  end, State, MsgList),
	    {noreply, State1}
    catch
	?EXCEPTION(error, _, Trace) ->
	    ?error("netlink: handle_info: Crash: ~p", 
		   [?GET_STACK(Trace)]),
	    {noreply, State}
    end;

handle_info({'DOWN',Ref,process,_Pid,_Reason}, State) ->
    case maps:take(Ref, State#state.subs) of
	error ->
	    {noreply,State};
	{_S,Subs} ->
	    ?debug("subscription from pid ~p deleted reason=~p",
		   [_Pid, _Reason]),
	    {noreply,State#state { subs=Subs }}
    end;
handle_info({timeout,Tmr,request_timeout}, State) ->
    R = State#state.request,
    if R#request.tmr =:= Tmr ->
	    ?debug("Timeout: ref current", []),
	    gen_server:reply(R#request.from, {error,timeout}),
	    State1 = State#state { request = undefined },
	    {noreply, dispatch_command(State1)};
       true ->
	    case lists:keytake(Tmr, #request.tmr, State#state.request_queue) of
		false ->
		    ?debug("Timeout: ref not found", []),
		    {noreply, State};
		{value,#request { from = From},Q} ->
		    ?debug("Timeout: ref in queue", []),
		    gen_server:reply(From, {error,timeout}),
		    State1 = State#state { request_queue = Q },
		    {noreply,dispatch_command(State1)}
	    end
    end;
handle_info({Tag, _Reply}, State) when is_reference(Tag) ->
    ?debug("INFO: SELF Reply=~p", [_Reply]),
    {noreply, State};    
handle_info(_Info, State) ->
    ?debug("INFO: ~p", [_Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

enq_request(Call, From, State) ->
    Tmr = erlang:start_timer(?REQUEST_TMO, self(), request_timeout),
    R = #request { tmr  = Tmr, 
		   call = Call,
		   from = From
		 },
    Q = State#state.request_queue ++ [R],
    State#state { request_queue = Q }.
    
dispatch_command(State) when State#state.request =:= undefined ->
    case State#state.request_queue of
	[R=#request { call = {get,What,Fam,Flags,Attrs} } | Q ] ->
	    R1 = update_timer(R),
	    State1 = State#state { request_queue = Q, request = R1 },
	    ?debug("dispatch_command: ~p", [R1]),
	    get_command(What,Fam,Flags,Attrs,State1);
	[R=#request { call = noop } | Q ] ->
	    R1 = update_timer(R),
	    State1 = State#state { request_queue = Q, request = R1 },
	    ?debug("dispatch_command: ~p", [R1]),
	    State1; %% let it timeout
	[] ->
	    State
    end;
dispatch_command(State) ->
    State.

update_timer(R = #request { tmr = {relative,Tmo} }) 
  when is_integer(Tmo), Tmo >= 0 ->
    Tmr = erlang:start_timer(Tmo, self(), request_timeout),
    R#request { tmr = Tmr };
update_timer(R = #request { tmr = Tmr }) when is_reference(Tmr) ->
    R.

update_sndbuf(Port, Min) ->
    case netlink_drv:get_sndbuf(Port) of
	{ok,Size} when Size >= Min ->
	    {ok,Size};
	{ok,_Size} ->
	    netlink_drv:set_sndbuf(Port, Min),
	    netlink_drv:get_sndbuf(Port);
	Err -> Err
    end.


update_rcvbuf(Port, Min) ->
    case netlink_drv:get_rcvbuf(Port) of
	{ok,Size} when Size >= Min ->
	    {ok,Size};
	{ok,_Size} ->
	    netlink_drv:set_rcvbuf(Port, Min),
	    netlink_drv:get_rcvbuf(Port);
	Err -> Err
    end.

get_command(link,Fam,Flags,Attrs,State) ->
    Seq = State#state.o_seq,
    Get = #getlink{family=Fam,arphrd=ether,index=0,
		   flags=[], change=[], attributes=Attrs},
    Hdr = #nlmsghdr { type  = getlink,
		      flags = Flags,
		      seq   = Seq,
		      pid   = State#state.ospid },
    Request = netlink_codec:encode(Hdr,Get),
    netlink_drv:send(State#state.port, Request),
    State#state { o_seq = (Seq+1) band 16#ffffffff };
get_command(addr,Fam,Flags,Attrs,State) ->
    Seq = State#state.o_seq,
    Get   = #getaddr{family=Fam,prefixlen=0,flags=[],scope=0,
		     index=0,attributes=Attrs},
    Hdr = #nlmsghdr { type=getaddr,
		      flags=Flags,
		      seq=Seq, 
		      pid=State#state.ospid },
    Request = netlink_codec:encode(Hdr,Get),
    netlink_drv:send(State#state.port, Request),
    State#state { o_seq = (Seq+1) band 16#ffffffff}.

handle_nlmsg(_RTM=#newlink{family=_Fam,index=Index,flags=Fs,change=Cs,
			  attributes=As}, State) ->
    ?debug("RTM = ~p", [_RTM]),
    IfName = proplists:get_value(ifname, As, ""),
    As1 = [{index,Index},{flags,Fs},{change,Cs}|As],
    Links = State#state.links,
    IfNames = State#state.ifnames,
    case maps:take(Index,Links) of
	error ->
	    Attr = update_attrs(IfName,link,As1,#{},State#state.subs),
	    Link = #link { index=Index, name=IfName, addr = #{}, attr=Attr },
	    IfNames1 = IfNames#{ IfName => Index },
	    State#state { links = Links#{ Index => Link },
			  ifnames = IfNames1 };
	{L,Links1} ->
	    Attr = update_attrs(IfName,link,As1,L#link.attr,State#state.subs),
	    Link = L#link { name = IfName, attr = Attr },
	    IfNames1 = IfNames#{ IfName => Index },
	    State#state { links = Links1#{ Index => Link },
			  ifnames = IfNames1 }
    end;
handle_nlmsg(_RTM=#dellink{family=_Fam,index=Index,flags=_Fs,change=_Cs,
			  attributes=As}, State) ->
    ?debug("RTM = ~p\n", [_RTM]),
    IfName = proplists:get_value(ifname, As, ""),
    Links = State#state.links,
    case maps:take(Index, Links) of
	error ->
	    ?warning("Warning link index=~w not found", [Index]),
	    State;
	{L,Links1} ->
	    IfNames = State#state.ifnames,
	    As1 = maps:to_list(L#link.attr),
	    update_attrs(IfName,link,As1,undefined,State#state.subs),
	    IfNames1 = maps:remove(L#link.name, IfNames),
	    State#state { links = Links1, ifnames = IfNames1 }
    end;
handle_nlmsg(_RTM=#newaddr { family=Fam, prefixlen=Prefixlen,
			     flags=Flags, scope=Scope,
			     index=Index, attributes=As },
	     State) ->
    ?debug("RTM = ~p", [_RTM]),
    Addr = proplists:get_value(address, As, {}),
    As1 = [{family,Fam},{prefixlen,Prefixlen},{flags,Flags},
	   {scope,Scope},{index,Index} | As],
    IfName = name_from_index(Index, State),
    case maps:take(Index, State#state.links) of
	error ->
	    ?warning("link ~w ~s does not exist\n", [Index,IfName]),
	    State;
	{L,Links} ->
	    Addrs0 = L#link.addr,
	    Addrs1 = 
		case maps:take(Addr, Addrs0) of
		    error ->
			Attr = update_attrs(IfName,addr,As1,#{},
					    State#state.subs),
			Addrs0#{ Addr => Attr };
		    {Attr0,Addrs01} ->
			Attr1 = update_attrs(IfName,addr,As1,Attr0,
					     State#state.subs),
			Addrs01#{ Addr => Attr1 }
		end,
	    L1 = L#link { addr = Addrs1 },
	    Links1 = Links#{ Index => L1 },
	    State#state { links = Links1 }
    end;

handle_nlmsg(_RTM=#deladdr { family=_Fam, index=Index, attributes=As },
	     State) ->
    ?debug("RTM = ~p", [_RTM]),
    %% FIXME: address should be uniq per Index then key is {Index,Addr}
    case maps:take(Index, State#state.links) of
	false ->
	    ?warning("Warning interface=~w not found", [Index]),
	    State;
	{L,Links} ->
	    Addr = proplists:get_value(address, As, {}),
	    IfName = name_from_index(Index, State),
	    Addrs0 = L#link.addr,
	    Addrs1 = 
		case maps:take(Addr, Addrs0) of
		    error ->
			?warning("Warning addr=~p for index=~w not found", 
				 [Addr,Index]),
			Addrs0;
		    {Attr0,Addrs01} ->
			As1 = maps:to_list(Attr0),
			update_attrs(IfName,addr,As1,undefined,
				     State#state.subs),
			Addrs01
		end,
	    L1 = L#link { addr = Addrs1 },
	    Links1 = Links#{ Index => L1 },
	    State#state { links = Links1 }
    end;
handle_nlmsg(#done { }, State) ->
    case State#state.request of
	undefined ->
	    dispatch_command(State);
	#request { tmr = Tmr, from = From, reply = Reply } ->
	    ?debug("handle_nlmsg: DONE: ~p", 
		   [State#state.request]),
	    erlang:cancel_timer(Tmr),
	    gen_server:reply(From, Reply),
	    State1 = State#state { request = undefined },
	    dispatch_command(State1)
    end;
handle_nlmsg(Err=#error { errno=Err }, State) ->
    ?debug("handle_nlmsg: ERROR: ~p", [State#state.request]),
    case State#state.request of
	undefined ->
	    dispatch_command(State);
	#request { tmr = Tmr, from = From } ->
	    ?debug("handle_nlmsg: DONE: ~p", 
		   [State#state.request]),
	    erlang:cancel_timer(Tmr),
	    %% fixme: convert errno to posix error (netlink.inc?)
	    gen_server:reply(From, {error,Err}),
	    State1 = State#state { request = undefined },
	    dispatch_command(State1)
    end;

handle_nlmsg(_RTM, State) ->
    ?debug("netlink: handle_nlmsg, ignore ~p", [_RTM]),
    State.

%% update attributes form interface "fName"
%% From to To Type is either link | addr
update_attrs(IfName,Type,As,undefined,Subs) ->
    lists:foreach(
      fun({K,Vold}) ->
	      send_event(IfName,Type,K,Vold,undefined,Subs)
      end, As),
    undefined;
update_attrs(IfName,Type,As,Map,Subs) ->
    lists:foldl(
      fun({K,Vnew},Mi) ->
	      case maps:find(K,Mi) of
		  error -> 
		      send_event(IfName,Type,K,undefined,Vnew,Subs),
		      Mi#{K => Vnew};
		  {ok,Vnew} -> Mi; %% already exist
		  {ok,Vold} ->
		      send_event(IfName,Type,K,Vold,Vnew,Subs),
		      Mi#{K => Vnew}
	      end
      end, Map, As).

%% Send changes in subscribed fields
%% FIXME match!?
send_event(IfName,Type,Field,Old,New,Subs) ->
    maps:fold(
      fun(_Ref,S,Count) when S#sub.name =:= IfName; 
			     S#sub.name =:= "*" ->
	      case event_filter(S#sub.match, Type, Field, New) of
		  true ->
		      S#sub.pid ! {netlink,S#sub.ref,IfName,Field,Old,New},
		      Count+1;
		  false ->
		      Count
	      end;
	 (_Ref,_S,Count) ->
	      Count
      end, 0, Subs).

event_filter(Ms, Type, Field, Value) when is_list(Ms) ->
    event_filter_any(Ms, Type, Field, Value);
event_filter(M, Type, Field, Value) ->
    event_filter_(M, Type, Field, Value).

event_filter_(?ANY, _, _, _)     -> true;
event_filter_(?ADDR, addr, _, _) -> true;
event_filter_(?LINK, link, _, _) -> true;
event_filter_({?ANY,Field}, _Type, Field, _Value) -> true;
event_filter_({?ANY,{Field,Value}}, _Type, Field, Value) -> true;
event_filter_({?ANY,{Op,Field,Value}}, _Type, Field, FValue) ->
    compare(Op, FValue, Value);
event_filter_({Type,Field}, Type, Field, _Value) -> true;
event_filter_({Type,{Field,Value}}, Type, Field, Value) -> true;
event_filter_({Type,{Op,Field,Value}}, Type, Field, FValue) ->
    compare(Op, FValue, Value);
event_filter_(Field, _Type, Field, _Value) -> true;
event_filter_({Field,Value}, _Type, Field, Value) -> true;
event_filter_({Op,Field,Value}, _Type, Field, FValue) ->
    compare(Op, FValue, Value);
event_filter_(_Match, _Type, _Field, _Value) ->
    false.

event_filter_any([H|T], Type, Field, Value) ->
    case event_filter_(H, Type, Field, Value) of
	true -> true;
	false -> event_filter_any(T, Type, Field, Value)
    end;
event_filter_any([], _Type, _Field, _Value) ->
    false.
    

match_interface(Index, State) when is_integer(Index) ->
    case maps:find(Index, State#state.links) of
	error  -> [];
	{ok,L} -> [L]
    end;
match_interface("*", State) ->
    maps:fold(fun(_Index,L,Acc) -> [L|Acc] end, [], State#state.links);
match_interface(IfName, State) when is_list(IfName) ->
    case maps:find(IfName, State#state.ifnames) of
	error -> [];
	{ok,Index} -> match_interface(Index, State)
    end;
match_interface(Addr, State) when is_tuple(Addr) ->
    %% search all interfaces for a matching address (may be more than one)
    maps:fold(
      fun(_Index,L,Ai) ->
	      maps:fold(
		fun(A, _Attr, Aj) ->
			if A =:= Addr -> [L|Aj];
			   true -> Aj
			end
		end, Ai, L#link.addr)
      end, [], State#state.links);
match_interface(Match, State) ->
    %% search all interfaces for a match
    maps:fold(
      fun(_Index,L,Ai) ->
	      case filter_match(Match, L#link.attr) of
		  true -> [L|Ai];
		  false -> Ai
	      end
      end, [], State#state.links).


name_from_index(Index, State) ->
    case maps:find(Index, State#state.links) of
	error -> undefined;
	{ok,L} -> L#link.name
    end.


match_link([L|Ls], Match) ->
    case match(Match, L#link.attr) of
	[] -> match_link(Ls, Match);
	As -> [As | match_link(Ls, Match)]
    end;
match_link([], _Match) ->
    [].

match_addr([L|Ls], Match) ->
    Ms = maps:fold(
	   fun(_Addr,Attr,Acc) ->
		   case match(Match, Attr) of
		       [] -> Acc;
		       As -> [As|Acc]
		   end
	   end, [], L#link.addr),
    Ms ++ match_addr(Ls, Match);
match_addr([], _Fields) ->
    [].
    

%% Run Match spec over Map and collect all matches
match(?ANY, Map) ->
    maps:to_list(Map);
match(Ms, Map) when is_list(Ms) ->
    match_(Ms, Map, []);
match(M, Map) ->
    case match1(M, Map) of
	error -> undefined;
	Match1 -> Match1
    end.

match_([M|Ms], Map, Acc) ->
    case match1(M, Map) of
	false -> match_(Ms, Map, Acc);
	Match1 -> match_(Ms, Map, [Match1|Acc])
    end;
match_([], _Map, Acc) ->
    Acc.

%% Check if any condition is true in match

filter_match(Ms, Map) when is_list(Ms) ->
    any_match(Ms, Map);
filter_match({any,Ms}, Map) ->
    any_match(Ms, Map);
filter_match({all,Ms}, Map) ->
    all_match(Ms, Map);
filter_match(M, Map) ->
    case match1(M, Map) of
	false -> false;
	_Match1 -> true
    end.

any_match([M|Ms], Map) ->
    case M of 
	{any,Ms1} ->
	    case any_match(Ms1, Map) of
		true -> true;
		false -> any_match(Ms,Map)
	    end;
	{all,Ms1} ->
	    case all_match(Ms1, Map) of
		true -> true;
		false -> any_match(Ms,Map)
	    end;
	_ ->
	    case match1(M, Map) of
		false -> any_match(Ms,Map);
		_Match1 -> true
	    end
    end;
any_match([], _Map) ->
    false.

all_match([M|Ms], Map) ->
    case M of 
	{any,Ms1} ->
	    case any_match(Ms1, Map) of
		false -> false;
		true -> all_match(Ms,Map)
	    end;
	{all,Ms1} ->
	    case all_match(Ms1,Map) of
		false -> false;
		true -> all_match(Ms,Map)
	    end;
	_ ->
	    case match1(M, Map) of
		false -> false;
		_Match1 -> all_match(Ms,Map)
	    end
    end;
all_match([], _Map) ->
    true.


%% match one match expression
match1({Op,Field,Value}, Map)
  when (is_atom(Op) andalso (is_atom(Field) orelse is_integer(Field))) ->
    case maps:find(Field, Map) of
	error -> false;
	{ok,FValue} ->
	    case compare(Op,FValue,Value) of
		true -> {Field,FValue};
		false -> false
	    end
    end;
match1({Field,Value}, Map) %% same as {'==',Field,Value}
  when (is_atom(Field) orelse is_integer(Field)) ->
    case maps:find(Field, Map) of
	{ok,Value} ->  {Field,Value};
	_ -> false
    end;
match1(Field,Map) when is_atom(Field); is_integer(Field) ->
    case maps:find(Field, Map) of
	error -> false;
	{ok,Value} -> {Field,Value}
    end;
match1(_Match,_Map) ->
    ?warning("unknown match condition ~p\n", [_Match]),    
    false.

format_link_attrs(AttrList,Verbose) ->
    lists:foldl(
      fun({af_spec,_V},A) -> A;
	 ({map,_V},A) -> A;
	 ({stats,_V},A) -> A;
	 ({stats64,_V},A) -> A;
	 ({change,_V},A) -> A;
	 ({K,V},A) when is_atom(K); Verbose ->
	      V1 = if K =:= linkinfo -> 
			   filter_kv(V, Verbose);
		      true -> V
		   end,
	      [["\n    ",name_to_list(K), " ",value_to_list(K,V1),";"]|A];
	 ({_K,_V},A) -> A
      end, [], AttrList).

format_addr_attrs(AttrList,Verbose) ->
    ["\n", "    addr {",
     lists:foldl(
       fun({cacheinfo,_V},A) -> A;
	  ({K,V},A) when is_atom(K); Verbose ->
	       [[" ",name_to_list(K), " ",value_to_list(K,V),";"]|A];
	  ({_K,_V},A) -> A
       end, [], AttrList), "}"].

filter_kv(List, _Verbose=true) -> List;
filter_kv(List, _Verbose=false) ->
    [KV || KV={K,_V} <- List, is_atom(K), K =/= data].

-spec name_to_list(Key::attr_name()) -> string().
name_to_list(K) when is_atom(K) ->
    atom_to_list(K);
name_to_list(K) when is_integer(K) ->
    integer_to_list(K).

-spec value_to_list(Key::attr_name(),Value::term()) -> string().
value_to_list(local,V)     -> format_a(V);
value_to_list(address,V)   -> format_a(V);
value_to_list(broadcast,V) -> format_a(V);
value_to_list(multicast,V) -> format_a(V);
value_to_list(anycast,V)   -> format_a(V);
value_to_list(_, V) -> io_lib:format("~p", [V]).

format_a(undefined) -> "";
format_a(A) when is_tuple(A), tuple_size(A) =:= 6 ->
    io_lib:format("~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b",
		  tuple_to_list(A));
format_a(A) when is_tuple(A), tuple_size(A) =:= 4 ->
    inet_parse:ntoa(A);
format_a(A) when is_tuple(A), tuple_size(A) =:= 8 ->
    inet_parse:ntoa(A).

%% add expressions ?
compare('==',A,B) -> A == B;
compare('=:=',A,B) -> A =:= B;
compare('<' ,A,B) -> A < B;
compare('=<' ,A,B) -> A =< B;
compare('>' ,A,B) -> A > B;
compare('>=' ,A,B) -> A >= B;
compare('/=' ,A,B) -> A /= B;
compare('=/=' ,A,B) -> A =/= B;
compare(_,_,_) -> false.

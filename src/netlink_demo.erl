%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    Tiny demo program of netlink, 
%%%    trying to detect when it is time to run ip application code
%%%    specially when binding to interfaces
%%% @end
%%% Created :  3 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(netlink_demo).

-export([start/0]).

start() ->
    application:start(netlink),
    spawn(fun() -> init() end).

init() ->
    %% NOTE: the interface list is normally empty, since netlink
    %% application populate the interface list async
    case netlink:getiflist() of
	{ok,List} ->
	    io:format("known interfaces: ~p\n", [List]);
	{error, Error} ->
	    io:format("netlink problem ~p\n", [Error])
    end,
    %% subscribe to interface flags
    {ok,Ref} = netlink:subscribe("*", 
				 [{link,ifname},
				  {link,flags},
				  {link,carrier},
				  {addr,address}]),
    loop(Ref, #{}).

%% typically we wait for an interface to be in "up" state before
%% * we want to attempt any thing on appliation level
%% * even better is to wait for carrier = 1
%%    carrier may start in carrier = 1 state which is bad!
%% * better than that, is to wait for flags to contain lower_up!
%%   which seem to be consisten
%% * better still, wait until the interface has got an address
%%   of the correct type, maybe even routable if wanted.
%%
-type uint8_t() :: 0..16#ff.
-type uint16_t() :: 0..16#ffff.

-type ipv4_addr() :: {uint8_t(),uint8_t(),uint8_t(),uint8_t()}.
-type ipv6_addr() :: {uint16_t(),uint16_t(),uint16_t(),uint16_t(),
		      uint16_t(),uint16_t(),uint16_t(),uint16_t()}.

-record(link_state,
	{
	 addr      :: undefined | ipv4_addr(),
	 addr6     :: undefined | ipv6_addr(),
	 status    :: undefined | up | down
	}).

loop(Ref, States) ->
    receive
	{netlink,Ref,IfName,Field,_Old,New} ->
	    %% io:format("~s: ~w  ~p => ~p\n", [IfName,Field,Old,New]),
	    LS0 = maps:get(IfName, States, #link_state{}),
	    Status =
		if Field =:= flags, is_list(New) ->
			case lists:member(lower_up, New) of
			    true -> up;
			    _ -> down
			end;
		   Field =:= flags, New =:= undefined ->
			down;
		   true ->
			LS0#link_state.status
		end,
	    Addr = if Field =:= address, tuple_size(New) =:= 4 -> New;
		      true -> LS0#link_state.addr
		   end,
	    Addr6 = if Field =:= address, tuple_size(New) =:= 8 -> New;
		       true -> LS0#link_state.addr6
		    end,
	    LS1 = LS0#link_state{status=Status,addr=Addr,addr6=Addr6},
	    if LS0 =/= LS1 ->
		    if LS0#link_state.status =/= up,
		       LS1#link_state.status =:= up ->
			    io:format("~s up\n", [IfName]),
			    %% if address already assigned
			    if LS1#link_state.addr =/= undefined ->
				    io:format("~s up, inet ~s\n",
					      [IfName,inet:ntoa(LS1#link_state.addr)]);
			       true ->
				    ok
			    end,
			    if LS1#link_state.addr6 =/= undefined ->
				    io:format("~s up, inet6 ~s\n",
					      [IfName,inet:ntoa(LS1#link_state.addr6)]);
			       true ->
				    ok
			    end;
		       LS0#link_state.status =:= up,
		       LS1#link_state.status =/= up ->
			    io:format("~s down\n", [IfName]);
		       true ->
			    ok
		    end,
		    if
			LS1#link_state.status =:= up,
			LS1#link_state.addr =/= undefined,
			LS0#link_state.addr =/= LS1#link_state.addr ->
			    io:format("~s up inet ~s\n",
				      [IfName,inet:ntoa(LS1#link_state.addr)]);
			true ->
			    ok
		    end,
		    if LS1#link_state.status =:= up,
		       LS1#link_state.addr6 =/= undefined,
		       LS0#link_state.addr6 =/= LS1#link_state.addr6 ->
			    io:format("~s up inet6 ~s\n",
				      [IfName,inet:ntoa(LS1#link_state.addr6)]);
		       true ->
			    ok
		    end;
	       true -> %% no change...
		    ok
	    end,
	    States1 = States#{ IfName => LS1 },
	    loop(Ref, States1);
	Other ->
	    io:format("Got ~p\n", [Other])
    end.

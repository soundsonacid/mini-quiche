# mini-quiche

this repo is updated at the end of each day that i work on it.

continuation of tiny implementation series

minimalist implementation of the QUIC transport protocol (v1) using only tokio and std library

this one will probably end up being pretty large just due to the nature of QUIC

i haven't quite figured out what this _is_ yet or what features i'll faithfully support

but i will soon, i'm trying to speedrun it (as best i can w/ real work)

the work-blog is totally ancillary to this project, but if for any reason you want to read my stream of consciousness please do!

## work-blog

### 7/30:

3:10 pm  
i spent a lot of time going back and forth between design for the headers today.  
i think that maybe i'm getting _too_ into the weeds on granular details, but at the same time i don't see any reason why that's necessarily bad.

3:29 pm  
writing the `bits_ext!` macro was a lot of fun.  it took a while though, so maybe i'm spending too much time on writing "cool" rust.  
on the other hand, this entire project is supposed to be an exercise in writing "cool" rust / learning about QUIC.  
i'll probably keep obsessing over the minutae - it's fun to do!

maybe in my real work i focus too much on getting the job done ASAP to standard S in time T.  
in my own code i take time maybe 1.5T to write it, but it gets done to standard maybe 1.3S.  
i think that this is a skill issue.

unfortunately i'm not totally sold on the implementation of `bits_ext!` in its current form.  feels like the additional `impl`s for the nice-to-have functions are aesthetically bad. i'll keep pondering on it.  gonna take a break for now.  

6:20 pm  
took like a 60 minute break. i spent more time than i should have figuring out how to encode & decode long packets, like 90 minutes maybe more.  a lot of weird bugs.  i think that the "fuzzing" i'm doing for these tests is going to pay dividends down the road and allow me to get bugs out before i build a lot on top of the fundamentals, so i'm gonna keep writing the randomly generated style tests for stuff like encode / decode.  

i still have to figure out how to do `ConnectionId.cid` exactly sized to the cid_len - maybe something as naive as a `Vec` will work out fine.

6:40 pm  
`Vec` works fine.  not really happy about the heap allocation tho vs using a slice. fiddled a little bit to try and get it to work nicely, but didn't happen. gonna spend ~20 minutes trying to make long header encode / decode cleaner before calling it for the day.  

TODO next time:  
1. short headers ✅
2. cleaner header encode / decode ✅
3. better `ConnectionId` data length stuff?  
4. start on `Packet`  


### 7/31:  

11:38 am  
while eating breakfast today i had a really neat macro idea to make encode / decode easier and generally make working with `Bits` objects more ergonomic.  going to try to implement it now while i wait for this other script to run.  

12:14 pm  
the `decompose_bits!` macro works!  i'm very happy about it, i think it is going to make dealing with individual bits substantially easier.  
now to come up with an equivalent for composing them... i think i'll do that later today tho.

12:25 pm  
i have realized that there is no reason for `decompose_bits!` to be a macro.  

1:12 pm  
got a bunch of real work done, took a walk.  turned `decompose_bits!` into a regular function and wrote its counterpart, `compose_bits`.  `compose_bits` was giving me a lot of weird trouble where it would only work right sometimes, eventually i fiddled around enough with it that it works fine now.  gonna try to fully implement short headers later today.  

2:36 pm  
apparently short header is 0 and long header form is 1? i am not sure how i confused the two.  found a pretty glaring bug in the `generate_random_long_header` by virtue of discovering that bug tho, so at least that is a win.

3:13 pm  
i'm glad that i did all the "optimizations" for decoding bits before i wrote short header encode / decode - it made it super formulaic & simple.  glad that i was able to get through it without too many issues!    

3:27 pm  
it's pretty hard to find any precise resources on headers.  i worry that i might have to totally redesign them (for the second time now).  
RFC-9000 only says stuff about particular types of packets, and the QUIC invariants (RFC-8999) say that bits 1-8 of the 0 byte are "version-specific bits".
i'm thinking that _maybe_ i'll end up making the 1-8 bits `SevenBits` or something?  i am going to stop building on them until i come to a head on packet design.  might work more on this later today still, but probably not.  


TODO next time:  
1. finalize a good `Header` design   
2. start on `Packet` ✅    

### 8/2  
10:45 am  
to be honest i think the setup that i have for headers is gonna work fine.  maybe that'll come back to bite me but i think that it should be all good.  going to start on packets today.  

3:32 pm  
just started actually working on this for the day, got through a pretty good amount of a basic packet setup so far.  encode/decode works for both short & long.  i'm pretty antsy to start on the real networking of the thing haha.  i am gonna move on to frames and try to get some networking set up before doing encryption & header protection, if i can get through frames today i think that'll be a pretty big win.   

4:30 pm  
read a little about frame types.  currently trying to land on a design that i won't have to redo at all, it's been a pain to be a little unsure of header designs.  making sure i measure twice and cut once on frames.  

6:54 pm  
spent the last hour reading about frames and writing comments to make sure i remember what i read and learned about frames.  going to try to put packets, frames, and headers all together now and hopefully have them all "done", or at least well-prototyped, tonight.  pouring a coffee.  

7:04 pm  
it's a good thing i poured a coffee.  apparently i have made a crippling blunder in the `LongHeader` design, and i have to figure out a different way to do it.  i do like the way quinn did it, but i really would like to NOT steal any code from quinn...    

7:52 pm  
extending these headers has proven to be not fun at all.  i ended up taking some pretty heavy inspiration from quinn for `VarInt`, but i came up with my own way to do the custom header types.  since everything is after the `src_cid` field, i'm just using an enum of extensions to hold all of that data.  writing encode / decode functions will be the death of me.  

honestly, probably going to call it here for the night.  i'm still a little sick and my brain is still feeling a little clogged, but that's no excuse.  i'm just having a hard time locking in. gonna go read about probability.  major skill issue.  tomorrow, i will get through headers, frames, packets, and start working on the handshake.  

TODO next time:  
1. Fix `LongHeader`  ✅   
2. Finish `Frame`    
3. Prototype handshake    

### 8/3
12:12 pm  
just finished `VarInt`.  pretty happy with it, i think it'll work well.  probably took like an hour or so?  gonna take a break for a couple hours to do some other stuff and then come back to this later.  i'm optimistic about today's progress!  

5:30 pm  
spent the last 30 minutes or so refactoring `LongHeader::decode()` to work and tests to pass, but now that i'm doing `Packet` long header decodes i'm realizing that i might have written myself into a wall here.  right now i can't really tell if there is a reliable way to identify how long a given `LongHeaderExtension` is with nothing but the raw bytes, or if there is, it's probably pretty annoying to do... i'll figure that out tho and try to get through at least `Packet` and `Frame` today.  i'm definitely behind where i wanted to be by this point.  

5:42 pm  
while putting off long header stuff and trying to clean up `Packet::decode()` for short headers, i seem to have found a pretty weird bug regarding `number_len` and `PacketNumber`s.  gonna figure this out before doing anything else.  maybe i'll have an idea about long headers in the process.  

5:50 pm  
lol.  figured it out.  i have no idea why i decided to reverse the bits of the encoded headers s.t. later fields are higher up in the first byte.  

i think that was a pretty stupid design decision but i'm almost too far along to go in and change it.  it shouldn't cause any problems as long as i keep it in mind though, so no big deal.  gonna try and figure out long header extensions now.  

i think that if i can keep all the slop and garbage code contained within `header.rs` i'll be fine, i just don't want the slop from there to infect other files lol.    

6:08 pm  
i thought that my test suite was fine, but i just cannot stop finding little hidden bugs!  it is good enough that my tests catch them, but i have to think "something isn't right here..." and then make a change for it to really show up in the tests.  i would like to figure out some way that any changes i make are going to break tests.  i'll have to think more on that.  

6:52 pm  
ok.  figured out a way to do it that's bad but not _horrible_, and the slop is contained within `header.rs`, so things are all good.  going to finish `Frame` now and stat integrating them with `Packet` in hopes of being able to start working on the handshake either tonight (if i'm lucky) or tomorrow.  

7:30 pm  
i think i've landed on a pretty good design for `Frame`.  granted, i did take a lot of inspiration from quinn regarding what makes sense to do.  i think it's fair to have taken some code from quinn, even though i didn't really want to, it just sped up the process a lot.  i'm not doing this to learn rust, i'm doing this to learn quic.  

8:35 pm  
took a walk.  on the walk i realized that the reversing bits of encoding headers choice violates the spec.  going to fix that.  

9:39 pm  
i am just building on a mountain of debt right now, i can feel it.  the amount of time it took for me to fix the reversing bits bug was incredible - i've been working on it for the last hour and just finished it.  i _think_ that since all the debt is internal logic and not spec-violating stuff (specifically the way the `Bits` object works) it _should_ be fine?  i am pretty sure that i am able to ingest stuff according to the quic spec and properly encode / decode it, but i'm still not sure.  i guess we'll find out!  probably going to call it here for tonight.  

not super satisfied with the forward progress today (didn't finish `Frame` or start handshake), but i am glad that i got a lot of really nasty bugs solved and out of the way.  

TODO next time:
1. Finish `Frame` ✅    
2. Prototype handshake   

### 8/14    

11:06 am    
it has been a while since i worked on this but i am not gonna let it die.  getting `Frame` done today.    

2:38 pm    
i didn't do much for a couple hours but i just ran through `Frame::decode()` as fast as i could, going to test it now & hopefully it works fine!  i've been pretty lucky with the decodes so i'm hoping that i am lucky with this one too...     

3:14 pm     
it took forever to write the random `Frame` generation function, but i'm glad i did because i am finding all sorts of code that i wrote that i am having a hard time understanding why i ever wrote it like that LOL.  there's just a lot of weird stuff that was going wrong in `Frame` but nothing so hard that it's irritating really.     

3:38 pm    
i am having annoying problems with `ConnectionClose` frames.  i think that this is the last bug in `Frame::encode()` / `Frame::decode()` so hopefully i am able to finish it quickly.  i would like to put everything together into packets today...    

3:53 pm    
total victory against `Frame` has been accomplished.  time to try and put it all together into `Packet`!   

3:54 pm   
i lied.  as soon as i changed to 1m random `Frame`s i'm back with the same errors.  FUCK.  it seems to be pretty random when it'll break now, way less common.  probably some edge case?   

4:24 pm   
lol.  it wasn't a problem in the actual logic.  it was a problem in the random generation.  great way to spend an hour.  gonna try to put `Packet` together and then add a bunch of checks and balances on `Frame` to make sure that everything is all good there.   

4:37 pm   
kinda realizing that the "fuzz" for `Packet` is gonna be really annoying.  seems like i've been spending more time writing and debugging the random testing generation than the actual code.  i guess that's the unsexy, boring work that makes up most of the job though.  the best developer i ever worked with once told me that the rigorous, annoying, boring testing is what really makes you good.  

4:53 pm    
ok, it seems like 10,000 short header packets went pretty smoothly... which i'm a _little_ wary of, but i also feel like there's a good chance i could have just done my job properly here and it actually does work.  we will find out later i guess.    

5:05 pm  
i have found out.  it was not my programming acumen.  i was doing something wrong.  time to fix it!  

5:13 pm  
short header packets are just an issue with stream frames, so hopefully i can make short work of it.  i estimate long header packets will be slightly more difficult, but maybe not.  the testing for this project is getting to the "total slop" point of things which kinda sucks, i'd really like to get the testing a little cleaner.  maybe that will be next time's goal before anything else, just make the testing framework not so messy and bloated.   

5:19 pm   
ok that wasn't bad.  i was just wrongfully inserting frames after a stream frame that should occupy the rest of the packet.  easy fix.  

5:41 pm   
long packet decode works fine, but i'm noticing some really strange behavior!  the long packet type is continually coming out always as initial, which obviously is not ideal for testing coverage... i'll have to dig a little deeper to figure out why that's happening.   

5:54 pm    
apparently this behavior is exhibited in several places.  after writing a better rng multiple tests fail.  i have certainly learned my lesson about checking what values are actually going into these tests.    

### 8/15   

8:49 am   
yesterday i got caught up playing a four hour long game of catan and didn't get to fix this.  i am going to fix it this morning.   

9:44 am   
all tests passing, very cool.  now `Packet` is mostly complete!  all that's left to do is add error checking on `Frame` and then i should be good to start building on top of it.   

10:34 am    
fixing this random generation over and over to make it adhere to quic is really annoying honestly.   

11:05 am   
that was actually not that bad, i was just getting frustrated with the ack / ack_ecn no negative packet numbers thing for a second.  all the other errors were really simple.  now that `Packet` seems to be fully done, i'm gonna plan out next steps.    

4:44 pm   
ok i did a bunch of ideas around `Connection` but i'm not really anywhere substantial with it.  feeling kinda burnt out on this for the day so going to call it here and try to flesh connection out more tomorrow   

TODO next time:   
1. flesh out `Connection`   
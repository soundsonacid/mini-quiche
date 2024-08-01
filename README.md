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
2. start on `Packet`
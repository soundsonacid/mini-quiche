# mini-quiche

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
1. short headers
2. cleaner header encode / decode
3. better `ConnectionId` data length stuff?
4. start on `Packet`
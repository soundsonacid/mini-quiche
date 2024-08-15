use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<u64> = RefCell::new(0x123456789ABCDEF);
}

pub fn rand(modulus: u128) -> u8 {
    if modulus == 0 {
        return 0;
    }

    RNG.with(|rng| {
        let mut state = rng.borrow_mut();
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (((*state >> 32) as u128) % modulus) as u8
    })
}

use paillier::*;
use threshold_secret_sharing as tss;

fn main() {
    let (ek, dk) = Paillier::keypair().keys();

    let ref tss = tss::shamir::ShamirSecretSharing {
        threshold: 1,
        share_count: 2,
        prime: 7757  // any large enough prime will do
    };

    // x = x1 + x2
    // y = y1 + y2
    // w = xy = (x1+x2)*(y1+y2)
    
    //x = 62
    let x1 = 27;
    let x2 = 35;

    //y = 97
    let y1 = 71;
    let y2 = 26;
    
    // w should be 6014

    let x1_enc = Paillier::encrypt(&ek, x1);
    let y1_enc = Paillier::encrypt(&ek, y1);

    // player 2 generates r
    let r = 17;

    //player 2 computes this with homomorphic encryption:
    let t = Paillier::add(&ek,
        Paillier::add(&ek,
            Paillier::mul(&ek, x1_enc, y2),
            Paillier::mul(&ek, y1_enc, x2),
        ),
        r
    );

    // player 2 computes W2
    let w2 = (((x2 * y2)%7757) - r) % 7757;

    // player 1 computes w1
    let w1 = (((x1 * y1)%7757) + Paillier::decrypt(&dk, t))%7757;

    println!("w1: {} w2: {}", w1, w2);

    println!("{} * {} = {}", (x1+x2), (y1+y2), (x1+x2)*(y1+y2));
}

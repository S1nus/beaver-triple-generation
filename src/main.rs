use paillier::*;
use threshold_secret_sharing as tss;
use std::convert::TryInto;

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

    // We now have beaver triples, and we can multiply values
    // "A" will be player 1's input
    // "B" will be player 2's input
    // The players wish to compute C = A*B without revealing A or B
    
    let a = 7;
    let b = 2;

    let a_shares = tss.share(a);
    let b_shares = tss.share(b);

    let x1_shares = tss.share(x1.try_into().unwrap());
    let x2_shares = tss.share(x2.try_into().unwrap());

    let y1_shares = tss.share(y1.try_into().unwrap());
    let y2_shares = tss.share(y2.try_into().unwrap());

    let w1_shares = tss.share(w1.try_into().unwrap());
    let w2_shares = tss.share(w2.try_into().unwrap());

    // d = a - x
    let d0 = a_shares[0] - (x1_shares[0] + x2_shares[0])%7757;
    let d1 = a_shares[1] - (x1_shares[1] + x2_shares[1])%7757;
    // reveal d
    let d_revealed = tss.reconstruct(&[0,1], &[d0, d1]);
    let d_actual = a - (x1 as i64 + x2 as i64);
    println!("d: {} should be: {}", d_revealed, d_actual);

    // e = b - y
    let e0 = b_shares[0] - (y1_shares[0] + y2_shares[0])%7757;
    let e1 = b_shares[1] - (y1_shares[1] + y2_shares[1])%7757;
    let e_revealed = tss.reconstruct(&[0,1], &[e0, e1]);
    let e_actual = b - (y1 as i64 + y2 as i64);
    println!("e: {} should be: {}", e_revealed, e_actual);

    // then [z] = [w] + [x]*e + [y]*d -e*d
    // but apparently, only one party adds e*d to the shares...
    
    let z0 = (w1_shares[0]+w2_shares[0])%7757 as i64 + (( (x1_shares[0]+x2_shares[0])%7757 * e_revealed ) % 7757) +
        (( (y1_shares[0] + y2_shares[0])%7757 * d_revealed ) % 7757)
        - ((e_revealed*d_revealed)%7757);
    let z1 = (w1_shares[1]+w2_shares[1])%7757 as i64 + (( (x1_shares[1]+x2_shares[1])%7757 * e_revealed ) % 7757) +
        (( (y1_shares[1] + y2_shares[1])%7757 * d_revealed ) % 7757);

    let z_revealed = tss.reconstruct(&[0,1], &[z0, z1]);
    let z_actual = a*b;
    println!("z_revealed: {} z_actual: {}", z_revealed, z_actual);
}

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
    let x1 = 9;
    let x2 = 8;

    //y = 97
    let y1 = 3;
    let y2 = 4;
    
    // w should be 119

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
    let w2_shares = tss.share(w2 as i64);

    // player 1 computes w1
    let w1 = (((x1 * y1)%7757) + Paillier::decrypt(&dk, t))%7757;
    let w1_shares = tss.share(w1 as i64);

    println!("w1: {} w2: {}", w1, w2);

    println!("{} * {} = {}", (x1+x2), (y1+y2), (x1+x2)*(y1+y2));

    // We now have beaver triples, and we can multiply values
    // "A" will be player 1's input
    // "B" will be player 2's input
    // The players wish to compute C = A*B without revealing A or B
    
    let a = 7;
    let a_shares = tss.share(a);
    let b = 2;
    let b_shares = tss.share(b);

    let a_shares = tss.share(a);
    let b_shares = tss.share(b);

    let x1_shares = tss.share(x1.try_into().unwrap());
    let x2_shares = tss.share(x2.try_into().unwrap());

    let y1_shares = tss.share(y1.try_into().unwrap());
    let y2_shares = tss.share(y2.try_into().unwrap());

    let w1_shares = tss.share(w1.try_into().unwrap());
    let w2_shares = tss.share(w2.try_into().unwrap());

    println!("A: {}", a);
    println!("B: {}", b);

    let d = (b - (x1 as i64 + x2 as i64)+tss.prime)%tss.prime;
    let e = (a - (y1 as i64 + y2 as i64)+tss.prime)%tss.prime;
    println!("d: {} e: {}", d, e);

    let d_0 = (b_shares[0] - (x1_shares[0] +x2_shares[0])%tss.prime)%tss.prime;
    let d_1 = (b_shares[1] - (x1_shares[1] +x2_shares[1])%tss.prime)%tss.prime;
    let d_revealed = (tss.reconstruct(&[0,1], &[d_0, d_1])+tss.prime)%tss.prime;
    println!("d_revealed: {}", d_revealed);

    let e_0 = (a_shares[0] - (y1_shares[0] +y2_shares[0])%tss.prime)%tss.prime;
    let e_1 = (a_shares[1] - (y1_shares[1] +y2_shares[1])%tss.prime)%tss.prime;
    let e_revealed = (tss.reconstruct(&[0,1], &[e_0, e_1])+tss.prime)%tss.prime;
    println!("e_revealed: {}", e_revealed);

    let w = w1 + w2;
    println!("w: {}", w);
    let w0 = w1_shares[0] + w2_shares[0];
    let w1 = w1_shares[1] + w2_shares[1];
    let w_revealed = (tss.reconstruct(&[0,1], &[w0, w1])+tss.prime)%tss.prime;
    println!("W revealed: {}", w_revealed);

    let be_0 = (b_shares[0] * e_revealed)%tss.prime;
    let be_1 = (b_shares[1] * e_revealed)%tss.prime;

    let ad_0 = (a_shares[0] * d_revealed)%tss.prime;
    let ad_1 = (a_shares[1] * d_revealed)%tss.prime;

    let z0 = ((w1_shares[0] + w2_shares[0])%tss.prime + be_0 + ad_0 - (e_revealed*d_revealed)%tss.prime)%tss.prime;
    let z1 = ((w1_shares[1] + w2_shares[1])%tss.prime + be_1 + ad_1)%tss.prime;

    let z_revealed = tss.reconstruct(&[0,1], &[z0,z1]);
    println!("z: {}", z_revealed);

}

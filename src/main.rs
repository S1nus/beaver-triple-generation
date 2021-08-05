use paillier::*;
use threshold_secret_sharing as tss;
use std::convert::TryInto;

fn main() {
    let (ek1, dk1) = Paillier::keypair().keys();
    let (ek2, dk2) = Paillier::keypair().keys();

    let ref tss = tss::shamir::ShamirSecretSharing {
        threshold: 1,
        share_count: 2,
        prime: 7757  // any large enough prime will do
    };

    // x = x1 + x2 + x3
    // y = y1 + y2 + y3
    // w = xy = (x1+x2+x3)*(y1+y2+y3)
    
    //x =22 
    let x1 = 9;
    let x2 = 8;
    let x3 = 5;

    //y = 14 
    let y1 = 3;
    let y2 = 4;
    let y3 = 7;
    
    // w should be 308

    let x1_enc = Paillier::encrypt(&ek1, x1);
    let y1_enc = Paillier::encrypt(&ek1, y1);

    // player 2 computes t_2_1:
    let r_2 = 7;
    let t_2_1 = Paillier::add(&ek1,
        Paillier::add(&ek1,
            Paillier::mul(&ek1, &x1_enc, y2),
            Paillier::mul(&ek1, x2, &y1_enc)
        ),
        r_2
    );

    let x2_enc = Paillier::encrypt(&ek2, x2);
    let y2_enc = Paillier::encrypt(&ek2, y2);

    // player 3 computes t_3_2
    let r_3_2 = 11;
    let t_3_2 = Paillier::add(&ek2,
        Paillier::add(&ek2,
            Paillier::mul(&ek2, x3, &y2_enc),
            Paillier::mul(&ek2, y3, &x2_enc)
        ),
        r_3_2
    );

    // player 3 computes t_3_1
    let r_3_1 = 5;
    let t_3_1 = Paillier::add(&ek1,
        Paillier::add(&ek1,
            Paillier::mul(&ek1, x3, &y1_enc),
            Paillier::mul(&ek1, y3, &x1_enc)
        ),
        r_3_1
    );

    // x1y1 + x1y2 + x2y1 + r_2 + x3y1 + x1y3 + r_3_1
    let w1 = ((x1*y1)%7757 + Paillier::decrypt(&dk1, &t_2_1) + Paillier::decrypt(&dk1, &t_3_1))%7757;
    // x2y2 - r_2
    let w2 = ((x2*y2)%7757 - r_2 + Paillier::decrypt(&dk2, t_3_2))  %7757;
    // x3y3 - r_3_1 - r_3_2
    let w3 = ((x3*y3)%7757 - r_3_1 - r_3_2)%7757;

    println!("total: {}", w1+w2+w3);
    println!("should be: {}", ((x1+x2+x3)*(y1+y2+y3))%7757);

}

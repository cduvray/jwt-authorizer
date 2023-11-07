#![allow(dead_code)]

use lazy_static::lazy_static;
use serde_json::{json, Value};

lazy_static! {
    pub static ref JWKS_RSA1: Value = json!({
        "keys": [{
            "kty": "RSA",
            "n": "2pQeZdxa7q093K7bj5h6-leIpxfTnuAxzXdhjfGEJHxmt2ekHyCBWWWXCBiDn2RTcEBcy6gZqOW45Uy_tw-5e-Px1xFj1PykGEkRlOpYSAeWsNaAWvvpGB9m4zQ0PgZeMDDXE5IIBrY6YAzmGQxV-fcGGLhJnXl0-5_z7tKC7RvBoT3SGwlc_AmJqpFtTpEBn_fDnyqiZbpcjXYLExFpExm41xDitRKHWIwfc3dV8_vlNntlxCPGy_THkjdXJoHv2IJmlhvmr5_h03iGMLWDKSywxOol_4Wc1BT7Hb6byMxW40GKwSJJ4p7W8eI5mqggRHc8jlwSsTN9LZ2VOvO-XiVShZRVg7JeraGAfWwaIgIJ1D8C1h5Pi0iFpp2suxpHAXHfyLMJXuVotpXbDh4NDX-A4KRMgaxcfAcui_x6gybksq6gF90-9nfQfmVMVJctZ6M-FvRr-itd1Nef5WAtwUp1qyZygAXU3cH3rarscajmurOsP6dE1OHl3grY_eZhQxk33VBK9lavqNKPg6Q_PLiq1ojbYBj3bcYifJrsNeQwxldQP83aWt5rGtgZTehKVJwa40Uy_Grae1iRnsDtdSy5sTJIJ6EiShnWAdMoGejdiI8vpkjrdU8SWH8lv1KXI54DsbyAuke2cYz02zPWc6JEotQqI0HwhzU0KHyoY4s",
            "e": "AQAB",
            "kid": "rsa01",
            "alg": "RS256",
            "use": "sig"
          }]
    });
    pub static ref JWKS_RSA2: Value = json!({
        "keys": [{
            "kty": "RSA",
            "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
            "e": "AQAB",
            "kid": "rsa02",
            "alg": "RS256",
            "use": "sig"
        }]
    });
    pub static ref JWKS_EC1: Value = json!({
        "keys": [{
          "kty": "EC",
          "crv": "P-256",
          "x": "MZiwc5EVP_E3vkd2oKedr4lWVMN9vgdyBBpBIVFJjwY",
          "y": "1npLU75B6M0mb01zUAVoeYJSDOlQJmvjBdqLPjJvy3Y",
          "kid": "ec01",
          "alg": "ES256",
          "use": "sig"
        }]
    });
}

pub const JWT_RSA1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYTAxIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.pmm8Kdk-SvycXIGpWb1R0DuP5nlB7w4QQS7trhN_OjOpbk0A8F_lC4BdClz3rol2Pgo61lcFckJgjNBj34DQGeTGOtvxdiUXNgi1aKiXH4AyPzZeZx30PgFxa1fxhuZhBAj6xIZKBSBQvVyjeVQzAScINRCBX8zfCaXSU1ZCUkJl5vbD7zT-cYIFU76we9HcIYKRXwTiAyoNn3Lixa1H3_t5sbx3om2WlIB2x-sGpoDFDjorcuJT1yQx3grTRTBzHyRBRjZ3e8wrMbiacy-m3WoEFdkssQgYi_dSQH0hvxgacvGWayK0UqD7O5UL6EzTA2feXbgA_68o5gfvSnM8CUsPut5gZr-gwVbQKPbBdCQtl_wXIMot7UNKYEiFV38x5EmUr-ShzQcditW6fciguuY1Qav502UE1UMXvt5p8-kYxw2AaaVd6iTgQBzkBrtvywMYWzIwzGNA70RvUhI2rlgcn8GEU_51Tv_NMHjp6CjDbAxQVKa0PlcRE4pd6yk_IJSR4Nska_8BQZdPbsFn--z_XHEDoRZQ1C1M6m77xVndg3zX0sNQPXfWsttCbBmaHvMKTOp0cH9rlWB9r9nTo9fn8jcfqlak2O2IAzfzsOdVfUrES6T1UWkWobs9usGgqJuIkZHbDd4tmXyPRT4wrU7hxEyE9cuvuZPAi8GYt80";
pub const JWT_RSA1_AUD1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYTAxIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiYXVkIjpbImF1ZDEiLCJhdWQyIl0sImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxNTE2MjM5MDIyfQ.Wzf2NZWdngKEGGkSP42sWxD9zw8rjarslbjtflQ1UQ4TsbhDgasoLUhL6D483xmt30vRQIjzLeTWlsERva1rhyeZuif0sr9wqsQge5VEBDEt5CUwwi2KVpNhC75leChCN1VcA9IKJ3LodICaCw4ks6wrAM_29AbbH8jxlyZc25d0uAGdbc99c6-aQhfRmW68GMN7dryGTXfAoIsl70AHrMOt-1Csn8qoMsBUE1uKOFsnA6c8rGzVeeHx5N6dvCpXEsE7_rP6GClGa0qBkb2v8llgSPpPZlIklf2NnZYr3WW_hy__-VGitJXiniUfhzWqqDv-K773aQ0532V8SdBHZ9r6Ib7gtRCUqRX7VcK-HdMM9SPyGCXb1qSwOD_XuqGJ58IInzb-B7zde4d18Fy6jVmf27FXRZYAMX4YMVeEZgXnurGtghRqboxGy9nFznOK_uK9XSJmDjsHrLSIKqat158OhDvPj0tDCz_a7fn3fk2Yd8-QPSJIFQanInHahlBMlSLS4F2p5QM48ynoIl56bjam7XOO8A6hQipBQDHkQ5IWJaKtckRIf7wzhfp9ptOsB2MYqVO9mX0IcOQB7ydpxuj0AWacp7Z5JjdrZDekKJIEoBEEIzoxGqnJsg9fu8jkx287jy8WxaJ13uMm7ql1zqDLWXQb_PCVwW9t-99hDyM";
pub const JWT_RSA2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYTAyIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.tWyA4ve2CY6GruBch_qIf8f1PgCEhqmrZ1J5XBuwO_v-P-PSLe3MWpkPAMdIDE5QE19ItUcGdJblhiyPb0tJJtrDHVYER7q8X4fOjQjY_NlFK6Bd1GtZS2DCA5EPxIX8l7Jpn8fPvbyamagLwnB_waQaYBteTGnOkLmz3F3sqC8KdO9lyu5v7BknC1f56ZOvr_DiInkTiAsTWqX4nS2KYRjcz4HcxcPO7O0CFXqcOTF_e3ntmq4rQV9LHCaEnuXj2WZtnX423CMkcG0uYzsnmWAMPB6IlDKejPnAJThMjjuJhze1gGbP1U8c53UbEhfHEZgJ2N634YEXMfsojZ5VzQ";
pub const JWT_EC1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.MvZm3Cxf78OQYpPkVGPAHaNf7GasHcvlF7ONJRxKVAntXbTru_dIdTRH0gz4xMIDg3a7HyfHWRLRhdxSNPjMPQ";
pub const JWT_EC1_AUD1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiYXVkIjpbImF1ZDEiLCJhdWQyIl0sImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxNTE2MjM5MDIyfQ.mFveRLl0SiceOPmv2UKZwaUUqVO-q7NcDkjcEUU4aoBz_YR2UuHtKnYw_TsYIkCz5uCCuwGgGRUeC9_-14GrWQ";
pub const JWT_EC2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDIifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.IRW3iOr-pwlDW-rFH_WRAwXZlk4qbxRRqrdJfm0XsGYmvp1Beqnj8L8jsMHtsJzs9PDsCEbwYXiU_u5vnOsIJA";
pub const JWT_EC1_EXP_KO: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJib2IiLCJleHAiOjE1MTYyMzkwMjIsIm5iZiI6MTUxNjIzOTAyMn0.MNmY66S3NgSAbWwZP0hfC5pme3SM7B3yvFhBFLQH-cU3enP0G8bBzDOhpjmli9uKQitkIQxffwu2Au9wTUraTQ";
pub const JWT_EC1_NBF_KO: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJib2IiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MjAwMDAwMDAwMH0.d5MRfwcToMxR7O7NEt3qUj-MUKKpG9BZW1w6ihyfN95ZULoMajr7mtYY2R2LS96oBYgp3OdlR4tkHmdqDpvCSA";
pub const JWT_ED1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImVkMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.5bFOZqc-lBFy4gFifQ_CTx1A3R6Nry71gdi7KH2GGvTZQC_ZI1vNbqGnWQhpR6n_jUd9ICUc0pPI5iLCB6K1Bg";
pub const JWT_ED2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImVkMDIifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.UMdAP1cJJmP7Bc-Um0-6oB4Bn52MwlhAzCTd5_-CiL6DjcJFzDq4rhBFz3HZbX4k0K228cCQosY9K8YfRWpjBQ";

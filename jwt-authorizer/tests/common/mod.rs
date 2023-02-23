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

pub const JWT_RSA1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYTAxIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiYXVkIjoiYXVkMSIsImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxNTE2MjM5MDIyfQ.d29YS5U-Cfur1DDxOeiYBxlEzRFQrVovuFdyIlrMpAfLLWudtpqiMxHKfTEM0ohHrk4ahf7nWhMamuiQUOEZSYpx7ze-4f47FGU4RxFLVSZw7VUWFrNYKkmRlgFsCbpdRLb5in6YDIaqrUnr2tqF9c3vUo_15lLgNn__xDG9_49A8UvbNFGvDm_z53aYGBPdgWVmwrRU5lmHH0tYcLMyiqQKfnM4jr__klIeVGBpJ2V_2qZyHvvevEtiiV7EGWZxaA-cYzeaO-_24nVBvPYrcdib84pz-a4JWhmnUobfzvtbdKEy12abxB2TvpzikBbX5etiDx92cPP_9Kf_51BncmwC_anRIwCSEe5TEgduihYS9yucOGgjP09sjlPPvdGAE6vcl35eR2fizJo7KU6Ol8DoUSDMhuPS-KQ_bFpCDK1iPtsXw514WZQZL1qXF61yd5QZ3wvckR8s_pV0XcFHWg_TpupNC3Yn6zlYU9l8NLkWiIudJVAM2pe-MSu292FyR2ytLISrNqHtk-e4_MIoviqyswvmtHZivoFWkq_CE2V9RyLX4WXaVEJLf4FihfCMFGZVfON2B8N2PfoPMuAlE1otQerbKwwR_TYjOFJRG1HdIDqvNDQ-LeJDKKX0NzCHwoJIqC-X7m6F1QIcaupOWnXyoSndvsi6g1jAlP_fTCI";
pub const JWT_RSA2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InJzYTAyIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJuYmYiOjE1MTYyMzkwMjJ9.tWyA4ve2CY6GruBch_qIf8f1PgCEhqmrZ1J5XBuwO_v-P-PSLe3MWpkPAMdIDE5QE19ItUcGdJblhiyPb0tJJtrDHVYER7q8X4fOjQjY_NlFK6Bd1GtZS2DCA5EPxIX8l7Jpn8fPvbyamagLwnB_waQaYBteTGnOkLmz3F3sqC8KdO9lyu5v7BknC1f56ZOvr_DiInkTiAsTWqX4nS2KYRjcz4HcxcPO7O0CFXqcOTF_e3ntmq4rQV9LHCaEnuXj2WZtnX423CMkcG0uYzsnmWAMPB6IlDKejPnAJThMjjuJhze1gGbP1U8c53UbEhfHEZgJ2N634YEXMfsojZ5VzQ";
pub const JWT_EC1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiYXVkIjoiYXVkMSIsImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxNTE2MjM5MDIyfQ.orTVTRdQnktCg1Ar_mo9IvN__5-s-q5oCZaUUWaL2I8HAkIq68GV6ACqvhrxQMB-OInX0hY9pBWGYbrFJjCwKA";
pub const JWT_EC2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDIifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiYXVkIjoiYXVkMSIsImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxNTE2MjM5MDIyfQ.QnsVM9CA11VpwDr6e_aHzxlLSXTQ7yVH5oxTR1yIWBPKnosjk1EIIBMcSjD81fZCrON2kX4TNkfSCxSCL8GI3g";
pub const JWT_EC1_EXP_KO: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJib2IiLCJleHAiOjE1MTYyMzkwMjIsIm5iZiI6MTUxNjIzOTAyMn0.MNmY66S3NgSAbWwZP0hfC5pme3SM7B3yvFhBFLQH-cU3enP0G8bBzDOhpjmli9uKQitkIQxffwu2Au9wTUraTQ";
pub const JWT_EC1_NBF_KO: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImVjMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJib2IiLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MjAwMDAwMDAwMH0.d5MRfwcToMxR7O7NEt3qUj-MUKKpG9BZW1w6ihyfN95ZULoMajr7mtYY2R2LS96oBYgp3OdlR4tkHmdqDpvCSA";
pub const JWT_ED1_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImVkMDEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiYXVkIjoiYXVkMSIsImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxNTE2MjM5MDIyfQ.U2eaP1EzRiLDRRPJTVjOMy4y40uAiW8MeryWJAjU-QPxU_PnuzatvrRjntTcdW7hXx0EWIezecJuXzp2UrBqAw";
pub const JWT_ED2_OK: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImVkMDIifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEiLCJzdWIiOiJiQGIuY29tIiwiYXVkIjoiYXVkMSIsImV4cCI6MjAwMDAwMDAwMCwibmJmIjoxNTE2MjM5MDIyfQ.xFrGhImKI1irksznuU9DoLk24bbdHhurbVRoUdZSb_FNlav1Jw49eMyKfeJUPy8IdMCtnG33K9xHuCRjm5IcAA";

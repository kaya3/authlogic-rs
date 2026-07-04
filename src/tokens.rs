use crate::{
    secret::Secret,
    to_from_str::{DisplayWrapper, ToFromStr},
};

pub(crate) fn pack<T: ToFromStr>(id: T, token: Secret) -> Secret {
    Secret(format!("{}{}{}", DisplayWrapper(id), T::EXCLUDED, token.0))
}

pub(crate) fn unpack<T: ToFromStr>(packed_token: Secret) -> Option<(T, Secret)> {
    let index = packed_token.0.find(T::EXCLUDED)?;
    let id = T::try_parse(&packed_token.0[..index])?;
    
    // Strip the id in-place. This leaves a copy of the last few bytes of the
    // token in the unused portion of the String allocation, but this will
    // still be zeroized correctly on drop.
    let mut token = packed_token;
    token.0.replace_range(0..index + 1, "");

    Some((id, token))
}

#[cfg(test)]
mod test {
    use super::{Secret, pack, unpack};
    
    #[test]
    fn test_pack() {
        let packed_token = pack(5, Secret("ABCDEFG".to_string()));
        assert_eq!("5.ABCDEFG", packed_token.expose());
    }
    
    #[test]
    fn test_unpack() {
        let (id, token) = unpack::<i64>(Secret("5.ABCDEFG".to_string())).unwrap();
        assert_eq!(5, id);
        assert_eq!("ABCDEFG", token.expose());
    }
    
    #[test]
    fn test_round_trip() {
        let id: i64 = 1234567;
        let raw_token = "Qwertyuiop";
        let token = Secret(raw_token.to_string());
        let (unpacked_id, unpacked_token) = unpack::<i64>(pack(id, token)).unwrap();
        assert_eq!(id, unpacked_id);
        assert_eq!("Qwertyuiop", unpacked_token.expose());
    }
}

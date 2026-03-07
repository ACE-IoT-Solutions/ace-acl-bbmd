/// BACnet packet inspection using rusty-bacnet's encoding crate.
///
/// Decodes raw NPDU bytes to extract source/dest network addresses,
/// then peeks at the APDU header to determine the service type.
/// All zero-copy via `bytes::Bytes`.
use bacnet_encoding::apdu::{self, Apdu};
use bacnet_encoding::npdu::{self, Npdu};
use bacnet_types::enums::{ConfirmedServiceChoice, UnconfirmedServiceChoice};
use bytes::Bytes;

/// Packet metadata extracted from BACnet NPDU + APDU headers.
#[derive(Debug, Default)]
pub struct InspectionResult {
    /// Source BACnet network number (from NPDU SADR).
    pub source_network: Option<u16>,
    /// First byte of source MAC address, used as a device proxy.
    pub source_device: Option<u32>,
    /// Destination BACnet network number (from NPDU DADR).
    pub dest_network: Option<u16>,
    /// First byte of dest MAC address, used as a device proxy.
    pub dest_device: Option<u32>,
    /// Detected message type string (matches our ACL rule vocabulary).
    pub message_type: &'static str,
}

/// Inspect raw NPDU bytes and return extracted metadata.
///
/// If decoding fails at any stage we return what we have so far —
/// the caller always gets *some* result (at minimum `message_type = "unknown"`).
pub fn inspect_packet(pdu_data: &[u8]) -> InspectionResult {
    let mut result = InspectionResult {
        message_type: "unknown",
        ..Default::default()
    };

    let data = Bytes::copy_from_slice(pdu_data);

    // --- NPDU ---
    let npdu = match npdu::decode_npdu(data) {
        Ok(n) => n,
        Err(_) => return result,
    };

    extract_npdu_addresses(&npdu, &mut result);

    if npdu.is_network_message {
        result.message_type = "network_message";
        return result;
    }

    // --- APDU (from NPDU payload) ---
    if npdu.payload.is_empty() {
        return result;
    }

    let apdu = match apdu::decode_apdu(npdu.payload) {
        Ok(a) => a,
        Err(_) => return result,
    };

    result.message_type = classify_apdu(&apdu);
    result
}

fn extract_npdu_addresses(npdu: &Npdu, result: &mut InspectionResult) {
    if let Some(src) = &npdu.source {
        result.source_network = Some(src.network);
        if !src.mac_address.is_empty() {
            result.source_device = Some(src.mac_address[0] as u32);
        }
    }
    if let Some(dst) = &npdu.destination {
        result.dest_network = Some(dst.network);
        if !dst.mac_address.is_empty() {
            result.dest_device = Some(dst.mac_address[0] as u32);
        }
    }
}

/// Map an APDU to one of our ACL message type strings.
fn classify_apdu(apdu: &Apdu) -> &'static str {
    match apdu {
        Apdu::UnconfirmedRequest(req) => classify_unconfirmed(req.service_choice),
        Apdu::ConfirmedRequest(req) => classify_confirmed(req.service_choice),
        _ => "unknown",
    }
}

fn classify_unconfirmed(sc: UnconfirmedServiceChoice) -> &'static str {
    if sc == UnconfirmedServiceChoice::WHO_IS { return "who_is"; }
    if sc == UnconfirmedServiceChoice::I_AM { return "i_am"; }
    if sc == UnconfirmedServiceChoice::WHO_HAS { return "who_has"; }
    if sc == UnconfirmedServiceChoice::I_HAVE { return "i_have"; }
    if sc == UnconfirmedServiceChoice::TIME_SYNCHRONIZATION { return "time_sync"; }
    if sc == UnconfirmedServiceChoice::UNCONFIRMED_COV_NOTIFICATION { return "cov_notification"; }
    if sc == UnconfirmedServiceChoice::UNCONFIRMED_TEXT_MESSAGE { return "text_message"; }
    if sc == UnconfirmedServiceChoice::UNCONFIRMED_PRIVATE_TRANSFER { return "private_transfer"; }
    "unconfirmed_request"
}

fn classify_confirmed(sc: ConfirmedServiceChoice) -> &'static str {
    if sc == ConfirmedServiceChoice::READ_PROPERTY { return "read_property"; }
    if sc == ConfirmedServiceChoice::WRITE_PROPERTY { return "write_property"; }
    if sc == ConfirmedServiceChoice::READ_PROPERTY_MULTIPLE { return "read_property_multiple"; }
    if sc == ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE { return "write_property_multiple"; }
    if sc == ConfirmedServiceChoice::SUBSCRIBE_COV { return "subscribe_cov"; }
    if sc == ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION { return "cov_notification"; }
    if sc == ConfirmedServiceChoice::CREATE_OBJECT { return "create_object"; }
    if sc == ConfirmedServiceChoice::DELETE_OBJECT { return "delete_object"; }
    if sc == ConfirmedServiceChoice::DEVICE_COMMUNICATION_CONTROL { return "device_comm_control"; }
    if sc == ConfirmedServiceChoice::REINITIALIZE_DEVICE { return "reinitialize_device"; }
    if sc == ConfirmedServiceChoice::CONFIRMED_PRIVATE_TRANSFER { return "private_transfer"; }
    if sc == ConfirmedServiceChoice::CONFIRMED_TEXT_MESSAGE { return "text_message"; }
    if sc == ConfirmedServiceChoice::ATOMIC_READ_FILE { return "atomic_read_file"; }
    if sc == ConfirmedServiceChoice::ATOMIC_WRITE_FILE { return "atomic_write_file"; }
    "confirmed_request"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_local_who_is() {
        // NPDU: version=1, control=0x00 (local, no routing)
        // APDU: 0x10 = UnconfirmedRequest, 0x08 = WhoIs
        let pdu = [0x01, 0x00, 0x10, 0x08];
        let result = inspect_packet(&pdu);
        assert_eq!(result.message_type, "who_is");
        assert!(result.source_network.is_none());
        assert!(result.dest_network.is_none());
    }

    #[test]
    fn test_global_broadcast_who_is() {
        // NPDU: version=1, control=0x20 (dest present), DNET=0xFFFF, DLEN=0, hop=255
        // APDU: WhoIs
        let pdu = [0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08];
        let result = inspect_packet(&pdu);
        assert_eq!(result.message_type, "who_is");
        assert_eq!(result.dest_network, Some(0xFFFF));
    }

    #[test]
    fn test_empty_data() {
        let result = inspect_packet(&[]);
        assert_eq!(result.message_type, "unknown");
    }

    #[test]
    fn test_garbage_data() {
        let result = inspect_packet(&[0xFF, 0xFF, 0xFF]);
        assert_eq!(result.message_type, "unknown");
    }
}

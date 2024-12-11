def test_malicious_inputs():
    malicious_cons1_value = ["1000", "1" * 10**6, "<script>alert('XSS')</script>"]
    malicious_cons2_value = ["1000", "999999", "<script>alert('XSS')</script>"]
    try:
        result, details = process_result_same_key_same(
            id1="rule1",
            id2="rule2",
            cons1_keys=["malicious_key1", "time", "price"],
            cons2_keys=["malicious_key1", "time", "price"],
            cons1_value=malicious_cons1_value,
            cons2_value=malicious_cons2_value,
            general_keys=["general_key1", "general_key2"]
        )
        assert False, "Malicious input should have been blocked"
    except ValueError as e:
        assert "Input string too long" in str(e) or "contains potentially dangerous characters" in str(e)



def test_valid_inputs():
    valid_cons1_value = ["2023-12-31", "1000", "50"]
    valid_cons2_value = ["2023-12-31", "1200", "50"]
    result, details = process_result_same_key_same(
        id1="rule1",
        id2="rule2",
        cons1_keys=["time", "price", "quantity"],
        cons2_keys=["time", "price", "quantity"],
        cons1_value=valid_cons1_value,
        cons2_value=valid_cons2_value,
        general_keys=["time", "price", "quantity"]
    )
    assert result is True
    assert "conflicting constraints" in details["reason"]

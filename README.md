# Final Project of CIS5370 Course Consistency Checking Vulnerabilities and Mitigation
### Instructor: Professor Ruimin Sun
### Team: Md Jafrin Hossain, Raja Shekar Reddy Seelam and Umme Nusrat Jahan
### Main Paper and Repo: https://github.com/13luoyu/intelligent-test

## Overview
This repository contains a Python-based rule validation system for identifying and resolving constraint conflicts. However, an initial security review uncovered vulnerabilities that allowed **jailbreak attacks**, enabling malicious inputs to bypass validation, overload the system, and potentially inject harmful scripts.

## Jailbreak Attack: What It Is
A jailbreak attack manipulates weaknesses in the logic to:
1. **Bypass Input Restrictions**: Supply unvalidated or overly large inputs to disrupt functionality.
2. **Overload Resources**: Use excessively long strings or deeply nested structures to exhaust CPU or memory.
3. **Inject Malicious Content**: Introduce harmful scripts or inputs that exploit downstream systems (e.g., XSS attacks in web contexts).




# Consistency Checking: Jailbreak Attack Analysis and Mitigation

## Overview
This repository contains a Python-based rule validation system for identifying and resolving constraint conflicts. 
However, an initial security review uncovered vulnerabilities that allowed **jailbreak attacks**, enabling malicious inputs to bypass validation, overload the system, and potentially inject harmful scripts.

---

## Security Issues

### 1. Resource Exhaustion
- The system allowed processing of excessively large inputs, leading to potential denial-of-service (DoS) attacks.
- Example of an attack:
```python
malicious_cons1_value = ["1000", "1" * 10**6, "<script>alert('XSS')</script>"]
malicious_cons2_value = ["1000", "999999", "<script>alert('XSS')</script>"]

result, details = process_result_same_key_same(
    id1="rule1",
    id2="rule2",
    cons1_keys=["malicious_key1", "time", "price"],
    cons2_keys=["malicious_key1", "time", "price"],
    cons1_value=malicious_cons1_value,
    cons2_value=malicious_cons2_value,
    general_keys=["general_key1", "general_key2"]
)
```

### 2. Injection Risks
- Inputs like `<script>alert('XSS')</script>` could propagate into downstream systems, creating a vector for cross-site scripting (XSS) attacks.

### 3. Weak Constraint Validation
- Regular expressions used in the logic did not limit input size or format, leaving the system vulnerable to ReDoS (Regex Denial of Service) attacks.

---

## Mitigation Strategies in Code

### Key Changes in `ours/consistency_checking.py`

#### Input Validation
Implemented a `validate_input` function to enforce size limits and block unsafe characters.

```python
def validate_input(value, max_length=1000, max_list_size=100):
    if isinstance(value, str) and len(value) > max_length:
        raise ValueError(f"Input string too long: {len(value)} characters (max {max_length})")
    if isinstance(value, list) and len(value) > max_list_size:
        raise ValueError(f"Input list too large: {len(value)} items (max {max_list_size})")
    if isinstance(value, str) and any(c in value for c in ['<', '>', '"', "'", ';']):
        raise ValueError(f"Input string contains potentially dangerous characters: {value}")
```

#### Regex Safeguards
Restricted regular expression matching to prevent ReDoS attacks.

```python
def safe_regex_match(pattern, text):
    if len(text) > 1000:  # Arbitrary limit to prevent abuse
        raise ValueError("Input too long for regex match")
    return re.fullmatch(pattern, text)
```

#### Error Handling
Integrated error handling to reject malicious inputs gracefully and avoid crashes.

---

### Enhanced Function Logic
The `process_result_same_key_same` function was updated to incorporate these safeguards.

```python
def process_result_same_key_same(id1, id2, cons1_keys, cons2_keys, cons1_value, cons2_value, general_keys):
    try:
        # Validate all inputs
        for value in cons1_value + cons2_value:
            validate_input(value)

        # Check for equality to quickly return if no conflict
        if cons1_value == cons2_value:
            return False, {}

        general_diff = False
        other_diff_idx = []
        for vi, v1 in enumerate(cons1_value):
            v2 = cons2_value[vi]
            if v1 != v2:
                if (is_time_key(cons1_keys[vi]) or is_num_key(cons1_keys[vi]) or is_price_key(cons1_keys[vi])):
                    if (
                        safe_regex_match(r"\d+", v1) and
                        safe_regex_match(r"\d+", v2)
                    ):
                        other_diff_idx.append(vi)
                        continue
                    else:
                        general_diff = True
                        break
                elif cons1_keys[vi] not in general_keys:
                    other_diff_idx.append(vi)
                    continue
                else:
                    general_diff = True
                    break

        if general_diff or len(other_diff_idx) >= 2:
            return False, {}
        else:
            reason = f"Rule {id1} and {id2} have conflicting constraints: "
            for idx in other_diff_idx:
                reason += f"{cons1_keys[idx]} differs with values {cons1_value[idx]} and {cons2_value[idx]} respectively. "
            return True, {"rule_ids": [id1, id2], "reason": reason}
    except ValueError as e:
        return False, {"error": str(e)}
```

---

## Testing and Results

### Valid Inputs
Tested with realistic constraints:
```python
valid_input_values1 = ["2023-12-31", "1000", "50"]
valid_input_values2 = ["2023-12-31", "1200", "50"]
result, details = process_result_same_key_same(
    id1="rule1",
    id2="rule2",
    cons1_keys=["time", "price", "quantity"],
    cons2_keys=["time", "price", "quantity"],
    cons1_value=valid_input_values1,
    cons2_value=valid_input_values2,
    general_keys=["time", "price", "quantity"]
)
print(result, details)
```
**Result**:
- Successfully identified conflicts without any issues:
  ```json
  {
      "rule_ids": ["rule1", "rule2"],
      "reason": "Rule rule1 and rule2 have conflicting constraints: price differs with values 1000 and 1200 respectively."
  }
  ```

### Malicious Inputs
Simulated a jailbreak attack with malicious values:
```python
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
    print(result, details)
except ValueError as e:
    print(f"Attack Blocked: {e}")
```
**Result**:
- **Blocked**: 
  ```json
  {
      "error": "Input string too long: 1000000 characters (max 1000)"
  }
  ```

---


---

## Acknowledgments
This project is meant to use for the final project code of our course CIS5370. This is for learning purspose and this is not industry ready. 
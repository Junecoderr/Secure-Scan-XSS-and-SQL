# XSS Detection and Prevention Testing

## Test 1
Input: Hello, welcome to my website!
Expected: No known suspicious pattern
Actual: No suspicious pattern detected.
Status: PASS

## Test 2
Input: Script element test string
Expected: Suspicious input detected
Actual: Suspicious input detected and input safely displayed
Status: PASS

## Test 3
Input: HTML event handler test string
Expected: Suspicious input detected
Actual: Suspicious input detected and input safely displayed.
Status: PASS

## Conclusion
The application was tested with normal and
suspicious inputs. Output encoding was used
to prevent submitted HTML from executing.
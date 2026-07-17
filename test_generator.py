"""
test_generator.py
=================
Intelligent, requirement-aware test-case generator.

Approach
--------
1. Analyse the Requirement Name + Requirement Details using a rich
   keyword/pattern ruleset to detect *domain categories* (authentication,
   file-upload, payment, API, etc.).
2. Assemble a tailored set of test cases that covers:
       Positive flow  |  Negative / invalid input
       Boundary values|  Validation & error-handling
       Security probes|  Edge & corner cases
       Performance / load hints where relevant
3. If no specific domain is detected, generate comprehensive generic
   functional test cases derived directly from the requirement text.

Every test case includes:
    TC ID, Objective, Description, Preconditions (embedded in Steps),
    Steps, Test Data, Expected Output, Requirement ID, Priority, Status,
    Pass/Fail
"""

import re
import textwrap
from typing import List, Dict, Any

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

COLUMNS = [
    "Sl. No.",
    "TC ID",
    "TC Objective",
    "TC Description",
    "TC Steps",
    "Test Data",
    "Expected Output",
    "Requirement ID",
    "Priority",
    "Status",
    "Pass/Fail",
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_case(
    sl: int,
    tc_id: str,
    objective: str,
    description: str,
    steps: List[str],
    test_data: str,
    expected: str,
    req_id: str,
    priority: str,
) -> Dict[str, Any]:
    numbered_steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
    return {
        "Sl. No.": sl,
        "TC ID": tc_id,
        "TC Objective": objective,
        "TC Description": description,
        "TC Steps": numbered_steps,
        "Test Data": test_data,
        "Expected Output": expected,
        "Requirement ID": req_id,
        "Priority": priority,
        "Status": "Not Executed",
        "Pass/Fail": "N/A",
    }


def _any_kw(text: str, keywords: List[str]) -> bool:
    """Return True if any keyword appears as a whole-word match."""
    tl = text.lower()
    for kw in keywords:
        pattern = r"\b" + re.escape(kw.lower()) + r"\b"
        if re.search(pattern, tl):
            return True
    return False


# ---------------------------------------------------------------------------
# Domain rule definitions
# Each rule: { keywords, req_id_prefix, cases[] }
# Each case:  { objective, description, steps[], data, expected, priority }
# ---------------------------------------------------------------------------

_DOMAIN_RULES: List[Dict] = [

    # ── Authentication / Login ────────────────────────────────────────
    {
        "keywords": ["login", "log in", "sign in", "signin", "authenticate", "authentication", "credential"],
        "label": "Authentication & Login",
        "req_id_prefix": "AUTH",
        "cases": [
            {
                "objective": "Verify successful login with valid credentials",
                "description": "Validates that a registered user can authenticate successfully using correct username and password, and is redirected to the appropriate landing page.",
                "steps": [
                    "Precondition: A valid user account exists in the system",
                    "Navigate to the application login page",
                    "Enter a valid, registered username in the Username field",
                    "Enter the correct password in the Password field",
                    "Click the 'Login' / 'Sign In' button",
                    "Observe the system response and resulting page",
                ],
                "data": "Username: validuser@example.com | Password: Secure@123",
                "expected": "User is authenticated successfully. The system displays the home/dashboard page. A session token or cookie is set. No error messages appear.",
                "priority": "High",
            },
            {
                "objective": "Verify login failure with an incorrect password",
                "description": "Ensures the system rejects login attempts when the password provided does not match the stored credentials for the given username.",
                "steps": [
                    "Precondition: A valid user account exists in the system",
                    "Navigate to the login page",
                    "Enter a valid, registered username",
                    "Enter an incorrect password",
                    "Click the Login button",
                    "Observe the error message and confirm no session is created",
                ],
                "data": "Username: validuser@example.com | Password: WrongPass999",
                "expected": "Login is rejected. An 'Invalid username or password' message is displayed. The user remains on the login page. No session or cookie is created.",
                "priority": "High",
            },
            {
                "objective": "Verify login with a non-existent username",
                "description": "Validates that the system does not reveal account existence by displaying a generic error for an unrecognised username.",
                "steps": [
                    "Navigate to the login page",
                    "Enter a username that has never been registered",
                    "Enter any password",
                    "Click the Login button",
                    "Observe the error message",
                ],
                "data": "Username: ghost_user_xyz@example.com | Password: AnyPass123",
                "expected": "A generic 'Invalid username or password' error is shown. The system does not indicate whether the username exists, preventing user enumeration.",
                "priority": "High",
            },
            {
                "objective": "Verify login is rejected when both fields are left empty",
                "description": "Checks that the form enforces required-field validation and prevents submission when no credentials are entered.",
                "steps": [
                    "Navigate to the login page",
                    "Leave the Username field blank",
                    "Leave the Password field blank",
                    "Attempt to click the Login button (or press Enter)",
                    "Observe the validation feedback",
                ],
                "data": "Username: (empty) | Password: (empty)",
                "expected": "The form does not submit. Inline validation messages appear on both fields indicating they are required.",
                "priority": "Medium",
            },
            {
                "objective": "Verify account lockout after consecutive failed login attempts",
                "description": "Validates the account lockout policy: after a defined number of failed attempts, the account is temporarily locked to prevent brute-force attacks.",
                "steps": [
                    "Precondition: The lockout threshold (e.g., 5 attempts) is configured",
                    "Navigate to the login page",
                    "Enter a valid username with an incorrect password",
                    "Repeat the failed login attempt until the lockout threshold is reached",
                    "Attempt one more login with correct credentials",
                    "Observe the system response",
                ],
                "data": "Username: validuser@example.com | Password: WrongPass (×5)",
                "expected": "After exceeding the threshold, the account is locked. A message such as 'Account temporarily locked. Try again in X minutes.' is displayed. Correct credentials are also rejected until the lockout period expires.",
                "priority": "High",
            },
            {
                "objective": "Verify the 'Remember Me' / session persistence functionality",
                "description": "Checks that selecting 'Remember Me' maintains the user session across browser restarts for the expected duration.",
                "steps": [
                    "Precondition: The 'Remember Me' feature is enabled in the application",
                    "Navigate to the login page",
                    "Enter valid credentials",
                    "Check the 'Remember Me' checkbox",
                    "Click Login",
                    "Close and reopen the browser",
                    "Navigate to the application URL",
                    "Observe whether the user is still logged in",
                ],
                "data": "Username: validuser@example.com | Password: Secure@123 | Remember Me: Checked",
                "expected": "The user remains logged in after reopening the browser. The persistent session cookie is set with the correct expiry duration.",
                "priority": "Medium",
            },
            {
                "objective": "Verify password field masks input characters",
                "description": "Ensures the password input field obscures characters as they are typed to protect credentials from shoulder surfing.",
                "steps": [
                    "Navigate to the login page",
                    "Click inside the Password field",
                    "Type any characters",
                    "Observe the characters displayed in the field",
                ],
                "data": "Password input: TestPassword1",
                "expected": "Each character is displayed as a bullet or asterisk (•). The actual text is not visible.",
                "priority": "Medium",
            },
            {
                "objective": "Verify login page is accessible only over HTTPS",
                "description": "Security check to confirm that the login page enforces an encrypted connection and redirects HTTP requests to HTTPS.",
                "steps": [
                    "Precondition: The server is configured for HTTPS",
                    "Open a browser and manually type the HTTP version of the login URL (e.g., http://...)",
                    "Press Enter and observe the redirection behaviour",
                ],
                "data": "URL: http://<application-domain>/login",
                "expected": "The browser is automatically redirected to the HTTPS version of the page (https://...). No credentials are transmitted over an unencrypted connection.",
                "priority": "High",
            },
        ],
    },

    # ── Registration / Sign-Up ─────────────────────────────────────────
    {
        "keywords": ["register", "registration", "sign up", "signup", "create account", "onboarding", "new user"],
        "label": "Registration & Sign-Up",
        "req_id_prefix": "REG",
        "cases": [
            {
                "objective": "Verify successful registration with all valid details",
                "description": "Validates the end-to-end happy path for creating a new user account using complete, valid information.",
                "steps": [
                    "Navigate to the Registration / Sign Up page",
                    "Enter a valid first name and last name",
                    "Enter a unique, valid email address",
                    "Enter a password that meets complexity requirements",
                    "Confirm the password in the 'Confirm Password' field",
                    "Fill in any additional required fields (phone number, date of birth, etc.)",
                    "Accept Terms & Conditions if required",
                    "Click the 'Register' / 'Create Account' button",
                    "Observe the confirmation message or redirect",
                ],
                "data": "Name: Jane Smith | Email: jane.smith@example.com | Password: Secure@2024 | Confirm: Secure@2024",
                "expected": "Account is created successfully. The system displays a success message or redirects to the login/home page. A confirmation email is sent to the registered address.",
                "priority": "High",
            },
            {
                "objective": "Verify registration is rejected for a duplicate email address",
                "description": "Ensures the system prevents two accounts from sharing the same email address.",
                "steps": [
                    "Precondition: An account with email 'existing@example.com' already exists",
                    "Navigate to the Registration page",
                    "Enter the email address that is already registered",
                    "Fill in the remaining fields with valid data",
                    "Submit the registration form",
                ],
                "data": "Email: existing@example.com | Password: Valid@123",
                "expected": "Registration fails. An error message such as 'An account with this email already exists' is displayed. No duplicate account is created.",
                "priority": "High",
            },
            {
                "objective": "Verify password strength enforcement during registration",
                "description": "Validates that the system rejects weak passwords and clearly communicates the complexity requirements.",
                "steps": [
                    "Navigate to the Registration page",
                    "Enter all other required fields with valid data",
                    "Enter a weak password (e.g., 'abc') in the Password field",
                    "Attempt to submit the form",
                    "Observe the validation message",
                ],
                "data": "Password: abc (too short, no uppercase, no digit, no special character)",
                "expected": "The form is not submitted. A validation message lists the unmet password requirements (e.g., minimum 8 characters, at least one uppercase letter, one digit, one special character).",
                "priority": "High",
            },
            {
                "objective": "Verify mismatch between Password and Confirm Password is flagged",
                "description": "Ensures real-time or on-submit validation catches when the two password fields do not match.",
                "steps": [
                    "Navigate to the Registration page",
                    "Enter a valid password in the 'Password' field",
                    "Enter a different value in the 'Confirm Password' field",
                    "Attempt to submit the form",
                ],
                "data": "Password: Secure@2024 | Confirm Password: Secure@2025",
                "expected": "The form is not submitted. An error message 'Passwords do not match' is displayed on or near the Confirm Password field.",
                "priority": "Medium",
            },
            {
                "objective": "Verify registration form validation for mandatory fields",
                "description": "Checks that all required fields enforce input before the form is submitted.",
                "steps": [
                    "Navigate to the Registration page",
                    "Leave all required fields blank",
                    "Click the Register button",
                    "Observe validation messages",
                ],
                "data": "All fields: (empty)",
                "expected": "Each required field shows an inline validation error. The form is not submitted. The page scrolls to or highlights the first invalid field.",
                "priority": "Medium",
            },
            {
                "objective": "Verify email format validation on the registration form",
                "description": "Validates that the system rejects malformed email addresses.",
                "steps": [
                    "Navigate to the Registration page",
                    "Enter an email address in an invalid format",
                    "Fill in other fields with valid data",
                    "Submit the form",
                ],
                "data": "Email: notanemail | also-invalid@@test.com",
                "expected": "The form is not submitted. An error message such as 'Please enter a valid email address' is displayed.",
                "priority": "Medium",
            },
            {
                "objective": "Verify the confirmation email is received after registration",
                "description": "End-to-end test ensuring the post-registration email workflow functions correctly.",
                "steps": [
                    "Complete a successful registration with a real or test email address",
                    "Check the inbox of the registered email account",
                    "Open the confirmation email",
                    "Click the account-activation link",
                    "Observe the resulting page",
                ],
                "data": "Email: testuser@mailtest.example.com",
                "expected": "A confirmation email arrives within a reasonable time (e.g., 2 minutes). The activation link is valid and activates the account. The user is redirected to a success/login page.",
                "priority": "High",
            },
        ],
    },

    # ── Search ─────────────────────────────────────────────────────────
    {
        "keywords": ["search", "find", "lookup", "query", "keyword search", "full-text"],
        "label": "Search & Filtering",
        "req_id_prefix": "SRCH",
        "cases": [
            {
                "objective": "Verify search returns accurate results for an exact-match keyword",
                "description": "Validates that entering a term that exactly matches a record's attribute returns that record in the search results.",
                "steps": [
                    "Precondition: At least one record containing the target keyword exists in the system",
                    "Navigate to the search page or locate the search bar",
                    "Enter the exact keyword that matches an existing record",
                    "Trigger the search (click Search button or press Enter)",
                    "Review the returned results",
                ],
                "data": "Search keyword: <exact name or identifier of an existing record>",
                "expected": "The matching record(s) are displayed. Results are relevant and correctly ranked or sorted. No unrelated results appear.",
                "priority": "High",
            },
            {
                "objective": "Verify search returns a 'No results found' message for an unmatched keyword",
                "description": "Ensures the system gracefully handles searches that yield no results.",
                "steps": [
                    "Navigate to the search page",
                    "Enter a keyword that is known to have no matching records",
                    "Trigger the search",
                    "Observe the page content",
                ],
                "data": "Search keyword: zzz_nonexistent_record_xyz987",
                "expected": "The results area displays a clear 'No results found' or equivalent message. The page does not throw an error or show a blank table without explanation.",
                "priority": "Medium",
            },
            {
                "objective": "Verify search with an empty query",
                "description": "Tests system behaviour when the user submits the search form without entering any keyword.",
                "steps": [
                    "Navigate to the search page",
                    "Leave the search input field empty",
                    "Click the Search button or press Enter",
                    "Observe the system response",
                ],
                "data": "Search keyword: (empty string)",
                "expected": "Either all records are returned (default list) or a validation prompt asks the user to enter a search term. No crash or unhandled exception occurs.",
                "priority": "Medium",
            },
            {
                "objective": "Verify partial/prefix search returns relevant results",
                "description": "Validates that entering only the beginning portion of a known value still retrieves matching records.",
                "steps": [
                    "Navigate to the search page",
                    "Enter the first 3–4 characters of a known record name",
                    "Trigger the search",
                    "Observe the returned results",
                ],
                "data": "Search keyword: first 3–4 characters of a known record",
                "expected": "All records whose names or descriptions begin with or contain the partial keyword are listed.",
                "priority": "Medium",
            },
            {
                "objective": "Verify search with special characters does not cause errors",
                "description": "Security and robustness test ensuring that special characters in the search input do not trigger SQL injection, XSS, or unhandled exceptions.",
                "steps": [
                    "Navigate to the search page",
                    "Enter a query containing special characters",
                    "Trigger the search",
                    "Observe the page response and server logs",
                ],
                "data": "Search keyword: ' OR 1=1; DROP TABLE users;-- | <script>alert(1)</script> | %20%27",
                "expected": "The system handles the input safely. Either no results are returned or a safe message is displayed. No SQL error, stack trace, or XSS execution occurs.",
                "priority": "High",
            },
            {
                "objective": "Verify search is case-insensitive",
                "description": "Ensures that the same records are returned regardless of the letter case used in the search keyword.",
                "steps": [
                    "Navigate to the search page",
                    "Search for a known record name in all lowercase",
                    "Note the results",
                    "Search again using all uppercase for the same keyword",
                    "Compare the two result sets",
                ],
                "data": "Search term 1: 'example name' | Search term 2: 'EXAMPLE NAME'",
                "expected": "Both searches return identical result sets, confirming case-insensitive matching.",
                "priority": "Medium",
            },
            {
                "objective": "Verify search result pagination when multiple pages of results exist",
                "description": "Tests that large result sets are properly paginated and navigation between pages works correctly.",
                "steps": [
                    "Precondition: More records exist than fit on a single page (e.g., > 10 or > 25 results per page)",
                    "Enter a broad keyword that returns many results",
                    "Trigger the search",
                    "Observe page 1 of results",
                    "Click 'Next' or page 2",
                    "Observe page 2 results",
                    "Navigate back to page 1",
                ],
                "data": "Search keyword: a very common term expected to return 50+ results",
                "expected": "Results are split across pages. Each page displays the correct subset of results. Navigation controls (Previous/Next/page numbers) function correctly. No duplicate results appear across pages.",
                "priority": "Medium",
            },
        ],
    },

    # ── File Upload ────────────────────────────────────────────────────
    {
        "keywords": ["upload", "file upload", "attach", "attachment", "import file", "document upload"],
        "label": "File Upload",
        "req_id_prefix": "FUPL",
        "cases": [
            {
                "objective": "Verify successful upload of a valid file within size and format limits",
                "description": "Validates the happy-path scenario for uploading a file that meets all system constraints.",
                "steps": [
                    "Precondition: The upload page is accessible and the user is authenticated",
                    "Navigate to the file upload section",
                    "Click 'Choose File' / 'Browse'",
                    "Select a file that is within the allowed size limit and of a permitted format",
                    "Click 'Upload'",
                    "Observe the confirmation message and file status",
                ],
                "data": "File: valid_document.pdf | Size: 2 MB | Format: PDF",
                "expected": "File is uploaded successfully. A success message is displayed. The file appears in the list of uploaded documents with correct metadata (name, size, date).",
                "priority": "High",
            },
            {
                "objective": "Verify upload is rejected for a file that exceeds the maximum size limit",
                "description": "Ensures the system enforces file size restrictions and provides a clear error for oversized files.",
                "steps": [
                    "Navigate to the file upload section",
                    "Click 'Choose File' and select a file larger than the permitted maximum",
                    "Attempt to upload the file",
                    "Observe the system response",
                ],
                "data": "File: large_file.pdf | Size: 55 MB (assuming 50 MB limit)",
                "expected": "The upload is rejected. An error message clearly states the maximum allowed file size (e.g., 'File size exceeds the 50 MB limit').",
                "priority": "High",
            },
            {
                "objective": "Verify upload is rejected for a disallowed file type",
                "description": "Tests that the system blocks file types that are not on the permitted list.",
                "steps": [
                    "Navigate to the file upload section",
                    "Select a file with a disallowed extension (e.g., .exe, .bat, .sh)",
                    "Attempt to upload",
                    "Observe the system response",
                ],
                "data": "File: malicious.exe | Format: Windows Executable",
                "expected": "The upload is blocked. An error message specifying the allowed file types is displayed. No file is stored on the server.",
                "priority": "High",
            },
            {
                "objective": "Verify upload behaviour when no file is selected",
                "description": "Checks that attempting to upload without selecting a file triggers appropriate validation.",
                "steps": [
                    "Navigate to the file upload section",
                    "Do not select any file",
                    "Click the Upload button",
                    "Observe the validation feedback",
                ],
                "data": "No file selected",
                "expected": "The form is not submitted. A message such as 'Please select a file before uploading' is displayed.",
                "priority": "Medium",
            },
            {
                "objective": "Verify that a file's content type cannot be spoofed via extension",
                "description": "Security test ensuring the server validates the actual file content/MIME type and not just the filename extension.",
                "steps": [
                    "Rename a disallowed file (e.g., an .exe) to a permitted extension (e.g., .pdf)",
                    "Navigate to the upload page",
                    "Attempt to upload the renamed file",
                    "Observe the system response",
                ],
                "data": "File: renamed_executable.pdf (actual content: PE executable)",
                "expected": "The server detects the MIME type mismatch and rejects the file with an appropriate error. The file is not stored.",
                "priority": "High",
            },
            {
                "objective": "Verify multiple concurrent file uploads are handled correctly",
                "description": "Tests system stability and data integrity when multiple files are uploaded simultaneously.",
                "steps": [
                    "Precondition: Multiple-file upload is supported by the application",
                    "Navigate to the upload page",
                    "Select 5 valid files simultaneously",
                    "Click Upload",
                    "Monitor upload progress and final state",
                ],
                "data": "Files: file1.pdf (1 MB), file2.jpg (500 KB), file3.xlsx (800 KB), file4.png (1.2 MB), file5.docx (400 KB)",
                "expected": "All five files are uploaded successfully and appear in the file list. No file is corrupted, truncated, or missing.",
                "priority": "Medium",
            },
        ],
    },

    # ── Password Management ────────────────────────────────────────────
    {
        "keywords": ["password", "reset password", "forgot password", "change password", "password policy"],
        "label": "Password Management",
        "req_id_prefix": "PWD",
        "cases": [
            {
                "objective": "Verify successful password reset via the 'Forgot Password' flow",
                "description": "End-to-end validation of the password reset workflow: from initiating the request to setting a new password.",
                "steps": [
                    "Navigate to the login page and click 'Forgot Password'",
                    "Enter the registered email address",
                    "Click 'Send Reset Link'",
                    "Open the received reset email",
                    "Click the password reset link",
                    "Enter a new valid password and confirm it",
                    "Submit the form",
                    "Attempt to log in with the new password",
                ],
                "data": "Email: user@example.com | New Password: NewSecure@2024",
                "expected": "A password reset email is sent. The link is valid and leads to the reset form. The new password is accepted. Login with the new password succeeds. Login with the old password fails.",
                "priority": "High",
            },
            {
                "objective": "Verify password reset link expires after its validity period",
                "description": "Security test ensuring that time-limited reset tokens cannot be reused after expiry.",
                "steps": [
                    "Initiate the password reset flow and receive the reset email",
                    "Wait until the link's expiry period has passed (e.g., > 24 hours)",
                    "Click the reset link",
                    "Observe the system response",
                ],
                "data": "Reset link used after expiry period (e.g., 24 hours)",
                "expected": "The system rejects the expired link and displays a message such as 'This reset link has expired. Please request a new one.'",
                "priority": "High",
            },
            {
                "objective": "Verify password cannot be changed to the current password",
                "description": "Validates the policy that prevents reuse of the existing active password during a change-password operation.",
                "steps": [
                    "Log in with valid credentials",
                    "Navigate to the Change Password section",
                    "Enter the current password in the 'Current Password' field",
                    "Enter the same password in the 'New Password' field",
                    "Submit the form",
                ],
                "data": "Current Password: Secure@123 | New Password: Secure@123 (same)",
                "expected": "The change is rejected. An error such as 'New password must differ from the current password' is displayed.",
                "priority": "Medium",
            },
            {
                "objective": "Verify Forgot Password with an unregistered email address",
                "description": "Security test ensuring the system does not reveal whether an email is registered.",
                "steps": [
                    "Navigate to the Forgot Password page",
                    "Enter an email address that is not registered",
                    "Click Send Reset Link",
                    "Observe the system message",
                ],
                "data": "Email: notregistered@example.com",
                "expected": "The system displays the same generic success message as for a valid email (e.g., 'If this email is registered, you will receive reset instructions'). No email is actually sent and no account details are disclosed.",
                "priority": "High",
            },
            {
                "objective": "Verify minimum password complexity requirements on change/reset",
                "description": "Validates the password policy during reset or change operations.",
                "steps": [
                    "Navigate to the Change Password or Reset Password form",
                    "Enter a new password that violates complexity rules (e.g., all lowercase, too short)",
                    "Submit the form",
                    "Observe the validation messages",
                ],
                "data": "New Password: pass (4 chars, no uppercase, no digit, no special character)",
                "expected": "The form is rejected. A clear list of unmet requirements is shown (minimum length, uppercase, digit, special character).",
                "priority": "Medium",
            },
        ],
    },

    # ── User Profile / Account Management ─────────────────────────────
    {
        "keywords": ["profile", "account", "user details", "update profile", "edit profile", "personal information", "my account"],
        "label": "User Profile",
        "req_id_prefix": "PROF",
        "cases": [
            {
                "objective": "Verify authenticated user can update profile information successfully",
                "description": "Validates the happy path for editing and saving user profile details.",
                "steps": [
                    "Log in as a registered user",
                    "Navigate to the Profile / My Account page",
                    "Click 'Edit Profile'",
                    "Update one or more fields (name, phone, address)",
                    "Click 'Save Changes'",
                    "Verify the updated information is reflected",
                ],
                "data": "Updated Name: Jane Doe | Updated Phone: +44-7700-900123",
                "expected": "Changes are saved successfully. A success confirmation message is displayed. The profile page immediately reflects the updated values.",
                "priority": "High",
            },
            {
                "objective": "Verify profile page is not accessible to unauthenticated users",
                "description": "Security check ensuring unauthenticated users are redirected away from the profile page.",
                "steps": [
                    "Ensure no active session exists (or clear cookies)",
                    "Directly navigate to the profile URL",
                    "Observe the system response",
                ],
                "data": "URL: /profile or /account | Authentication: None",
                "expected": "The user is redirected to the login page or receives a 401/403 response. Profile data is not exposed.",
                "priority": "High",
            },
            {
                "objective": "Verify profile update is rejected when required fields are cleared",
                "description": "Validates that mandatory profile fields cannot be removed/blanked during an edit.",
                "steps": [
                    "Log in and navigate to the Edit Profile page",
                    "Clear the value in a mandatory field (e.g., full name or primary email)",
                    "Click Save Changes",
                    "Observe validation feedback",
                ],
                "data": "Full Name: (cleared) | Email: (cleared)",
                "expected": "The save is rejected. Validation errors highlight the cleared required fields.",
                "priority": "Medium",
            },
            {
                "objective": "Verify email address change requires re-verification",
                "description": "Security validation ensuring that changing a profile's primary email triggers a verification step.",
                "steps": [
                    "Log in and navigate to the Edit Profile page",
                    "Change the email address to a new, valid address",
                    "Save changes",
                    "Observe whether a verification email is sent to the new address",
                ],
                "data": "New Email: newaddress@example.com",
                "expected": "A verification email is sent to the new address. The email change is not finalised until the link is clicked. The old email may also receive a security notification.",
                "priority": "High",
            },
        ],
    },

    # ── Payment / Checkout ─────────────────────────────────────────────
    {
        "keywords": ["payment", "checkout", "pay", "billing", "invoice", "transaction", "purchase", "credit card", "card", "stripe", "paypal"],
        "label": "Payment Processing",
        "req_id_prefix": "PAY",
        "cases": [
            {
                "objective": "Verify successful payment with a valid credit card",
                "description": "End-to-end validation of the payment flow using a valid test card.",
                "steps": [
                    "Precondition: Items are added to the cart/order",
                    "Proceed to the checkout/payment page",
                    "Enter valid credit card details (test card number, expiry, CVV)",
                    "Enter a valid billing address",
                    "Click 'Pay Now' / 'Place Order'",
                    "Observe the payment confirmation screen",
                ],
                "data": "Card: 4111 1111 1111 1111 | Expiry: 12/26 | CVV: 123 | Amount: $49.99",
                "expected": "Payment is processed successfully. An order confirmation is displayed. A confirmation email is sent. Transaction ID is provided.",
                "priority": "High",
            },
            {
                "objective": "Verify payment is declined for an invalid/expired card",
                "description": "Validates that the payment gateway correctly declines expired or invalid cards.",
                "steps": [
                    "Proceed to the checkout page",
                    "Enter an expired or invalid card number",
                    "Submit the payment",
                    "Observe the error message",
                ],
                "data": "Card: 4000 0000 0000 0002 (declined test card) | Expiry: 01/20 (expired)",
                "expected": "Payment is declined. A clear error message is shown (e.g., 'Your card was declined' or 'Card expiry date is in the past'). The order is not placed.",
                "priority": "High",
            },
            {
                "objective": "Verify payment page does not log or expose CVV",
                "description": "Security test confirming that CVV data is never stored in logs, cookies, or server-side persistence.",
                "steps": [
                    "Complete a payment using valid card details",
                    "Inspect the server logs, response body, and any stored order records",
                    "Check whether CVV or full card number is present anywhere",
                ],
                "data": "CVV: 123 | Card: 4111 1111 1111 1111",
                "expected": "CVV is never stored or logged. Only the last 4 digits of the card number are retained. All transmission uses TLS encryption.",
                "priority": "High",
            },
            {
                "objective": "Verify order total is calculated correctly including taxes and discounts",
                "description": "Validates the billing calculation logic for a checkout with applicable taxes and promotional discounts.",
                "steps": [
                    "Add items to the cart with known prices",
                    "Apply a valid discount/promo code",
                    "Proceed to checkout",
                    "Review the order summary before payment",
                ],
                "data": "Item: $40.00 | Discount: 10% ($4.00) | Tax: 8% ($2.88) | Expected Total: $38.88",
                "expected": "The order summary correctly shows subtotal, discount applied, tax amount, and final total. The amount charged matches the displayed total.",
                "priority": "High",
            },
            {
                "objective": "Verify payment failure triggers a graceful error and does not charge the user",
                "description": "Tests the system's handling of a network or gateway timeout during payment processing.",
                "steps": [
                    "Precondition: Simulate a payment gateway timeout (use test mode or network throttling)",
                    "Proceed to checkout and submit payment",
                    "Observe the system behaviour during and after the timeout",
                ],
                "data": "Simulated: Gateway timeout after 30 seconds",
                "expected": "The system displays an error message. The order is not marked as complete. The user's card is not charged (or any hold is released). The user is given the option to retry.",
                "priority": "High",
            },
        ],
    },

    # ── Notifications / Email ──────────────────────────────────────────
    {
        "keywords": ["notification", "email", "alert", "send email", "notify", "reminder", "message"],
        "label": "Notifications",
        "req_id_prefix": "NOTIF",
        "cases": [
            {
                "objective": "Verify trigger-based notification is sent on the correct event",
                "description": "Validates that an automated notification (email or in-app) is delivered when the associated trigger event occurs.",
                "steps": [
                    "Precondition: Notification triggers are configured in the system",
                    "Perform the action that should trigger the notification",
                    "Monitor the notification channel (email inbox or in-app notification centre)",
                    "Observe whether the notification is received",
                ],
                "data": "Trigger event: e.g. order placed, user registered, password changed",
                "expected": "The notification is received promptly (within defined SLA, e.g., 2 minutes). It contains the correct content, sender address, subject, and recipient.",
                "priority": "High",
            },
            {
                "objective": "Verify notification is not sent when the triggering event does not occur",
                "description": "Negative test ensuring no spurious notifications are generated in the absence of the trigger.",
                "steps": [
                    "Do not perform the trigger action",
                    "Monitor the notification channel for a defined period",
                    "Observe whether any unexpected notification arrives",
                ],
                "data": "No trigger event performed",
                "expected": "No notification is received. The notification log shows no entry for a trigger event.",
                "priority": "Medium",
            },
            {
                "objective": "Verify notification content includes all required dynamic data",
                "description": "Checks that personalised/dynamic fields (user name, order ID, etc.) are correctly populated in the notification.",
                "steps": [
                    "Trigger the notification by performing the associated action",
                    "Open the received notification",
                    "Inspect all dynamic fields",
                ],
                "data": "Expected dynamic fields: User Name, Order ID, Date, Amount, Application Link",
                "expected": "All dynamic fields are populated with the correct values relevant to the triggering event. No placeholder tokens (e.g., {{name}}) appear in the final notification.",
                "priority": "High",
            },
            {
                "objective": "Verify user can opt out of non-essential notifications",
                "description": "Tests the notification preference settings, ensuring users can disable optional alerts.",
                "steps": [
                    "Log in and navigate to Notification Preferences / Settings",
                    "Disable a specific notification type (e.g., marketing emails)",
                    "Save the preferences",
                    "Trigger an event that would generate the disabled notification",
                    "Check whether the notification is sent",
                ],
                "data": "Notification type: Marketing/Promotional Emails | Setting: Disabled",
                "expected": "The disabled notification type is not sent after the preference is saved. Other notification types remain unaffected.",
                "priority": "Medium",
            },
        ],
    },

    # ── Reporting / Dashboard ──────────────────────────────────────────
    {
        "keywords": ["report", "dashboard", "analytics", "chart", "graph", "statistics", "export", "summary"],
        "label": "Reporting & Analytics",
        "req_id_prefix": "RPT",
        "cases": [
            {
                "objective": "Verify dashboard displays accurate real-time data",
                "description": "Validates that key metrics and KPIs on the dashboard are current and calculated correctly.",
                "steps": [
                    "Log in with a user role that has dashboard access",
                    "Navigate to the Dashboard",
                    "Note the values of key metrics (e.g., total users, revenue, active sessions)",
                    "Independently verify the figures from the database or an alternative data source",
                ],
                "data": "Compare dashboard figures against database count queries",
                "expected": "Dashboard metrics match the independently verified data. Data is current (updated within the defined refresh interval).",
                "priority": "High",
            },
            {
                "objective": "Verify report generation with a valid date range",
                "description": "Tests the happy path for generating a report filtered by a specific start and end date.",
                "steps": [
                    "Navigate to the Reports section",
                    "Select a report type",
                    "Enter a valid start date and end date",
                    "Click Generate / Run Report",
                    "Review the output",
                ],
                "data": "Start Date: 01-Jan-2024 | End Date: 31-Mar-2024 | Report: Sales Summary",
                "expected": "The report is generated within an acceptable time. It includes only data from the specified date range. The total figures are accurate.",
                "priority": "High",
            },
            {
                "objective": "Verify report export to Excel/CSV is successful and data-accurate",
                "description": "Validates that the exported file contains all the data shown on-screen and is formatted correctly.",
                "steps": [
                    "Generate a report on-screen",
                    "Click the 'Export to Excel' or 'Export to CSV' button",
                    "Open the downloaded file",
                    "Compare the data in the file with the on-screen report",
                ],
                "data": "Report with 200 rows of data",
                "expected": "The exported file downloads successfully. All rows and columns are present and correctly formatted. No data is missing, truncated, or garbled.",
                "priority": "Medium",
            },
            {
                "objective": "Verify report is rejected when end date precedes start date",
                "description": "Input validation test for date range logic.",
                "steps": [
                    "Navigate to the Reports section",
                    "Enter an end date that is earlier than the start date",
                    "Click Generate",
                    "Observe the validation message",
                ],
                "data": "Start Date: 31-Dec-2024 | End Date: 01-Jan-2024",
                "expected": "The report is not generated. An error message such as 'End date must be after start date' is displayed.",
                "priority": "Medium",
            },
        ],
    },

    # ── API / Integration ──────────────────────────────────────────────
    {
        "keywords": ["api", "rest", "endpoint", "json", "webhook", "integration", "request", "response", "http", "service"],
        "label": "API Integration",
        "req_id_prefix": "API",
        "cases": [
            {
                "objective": "Verify API endpoint returns HTTP 200 with correct response body for a valid request",
                "description": "Happy-path test confirming the endpoint processes a well-formed request and returns the expected data structure.",
                "steps": [
                    "Precondition: Valid API credentials / token are available",
                    "Construct a well-formed HTTP request with required headers and valid payload",
                    "Send the request to the target endpoint",
                    "Inspect the HTTP status code and response body",
                ],
                "data": "Method: GET/POST | Endpoint: /api/v1/resource | Auth: Bearer <valid_token> | Payload: valid JSON",
                "expected": "HTTP 200 OK is returned. The response body is valid JSON matching the documented schema. All expected fields are present with correct data types.",
                "priority": "High",
            },
            {
                "objective": "Verify API returns HTTP 401 when the request is unauthenticated",
                "description": "Security test ensuring that endpoints are protected and reject unauthenticated calls.",
                "steps": [
                    "Construct a valid HTTP request to the endpoint",
                    "Omit the Authorization header or send an invalid/expired token",
                    "Send the request",
                    "Inspect the HTTP status code and error body",
                ],
                "data": "Authorization header: (omitted) or Bearer invalid_token",
                "expected": "HTTP 401 Unauthorized is returned. The response body contains an error message. No data is leaked.",
                "priority": "High",
            },
            {
                "objective": "Verify API returns HTTP 400 for a malformed or missing required field in the request body",
                "description": "Input validation test for the API endpoint.",
                "steps": [
                    "Construct an HTTP request with a missing or incorrectly typed required field",
                    "Send the request with valid authentication",
                    "Inspect the HTTP status code and error details in the response body",
                ],
                "data": "Missing field: 'user_id' | Or field with wrong type: user_id: 'abc' instead of integer",
                "expected": "HTTP 400 Bad Request is returned. The response body specifies which field(s) failed validation and why.",
                "priority": "High",
            },
            {
                "objective": "Verify API rate limiting returns HTTP 429 when the limit is exceeded",
                "description": "Tests that the API enforces rate limits and signals the client appropriately.",
                "steps": [
                    "Precondition: Rate limit is configured (e.g., 100 requests/minute)",
                    "Send requests to the endpoint rapidly, exceeding the configured limit",
                    "Observe the response on the request that exceeds the limit",
                ],
                "data": "101 rapid requests within 60 seconds",
                "expected": "HTTP 429 Too Many Requests is returned after the limit is exceeded. The response includes a Retry-After header or similar guidance. Earlier requests succeed.",
                "priority": "Medium",
            },
            {
                "objective": "Verify API response time is within the defined SLA",
                "description": "Performance test ensuring the endpoint responds within the acceptable latency threshold.",
                "steps": [
                    "Precondition: The SLA for response time is defined (e.g., < 500 ms for 95th percentile)",
                    "Send 50 sequential requests to the endpoint",
                    "Record the response time for each request",
                    "Calculate the average and 95th percentile response times",
                ],
                "data": "50 sequential requests with valid payloads",
                "expected": "All requests respond within the defined SLA. The 95th percentile is ≤ defined threshold. No request times out.",
                "priority": "Medium",
            },
            {
                "objective": "Verify API returns HTTP 404 for a request targeting a non-existent resource",
                "description": "Validates the error handling for requests to valid endpoints with non-existent resource IDs.",
                "steps": [
                    "Construct a request to a valid endpoint using a resource ID that does not exist",
                    "Send the request with valid authentication",
                    "Inspect the response",
                ],
                "data": "Resource ID: 99999999 (does not exist in the database)",
                "expected": "HTTP 404 Not Found is returned. The response body contains a descriptive error message.",
                "priority": "Medium",
            },
        ],
    },

    # ── Role-Based Access Control / Permissions ───────────────────────
    {
        "keywords": ["role", "permission", "access control", "rbac", "admin", "authorisation", "authorization", "privilege", "access level"],
        "label": "Role-Based Access Control",
        "req_id_prefix": "RBAC",
        "cases": [
            {
                "objective": "Verify admin user has access to all administrative functions",
                "description": "Validates that a user with the Administrator role can access and execute all admin-level operations.",
                "steps": [
                    "Log in with an account that has the Administrator role",
                    "Navigate to each administrative function (user management, settings, reports, etc.)",
                    "Attempt to perform a restricted admin action on each",
                    "Observe the outcome",
                ],
                "data": "Role: Administrator | Actions: create user, delete user, change settings, view all reports",
                "expected": "All administrative pages are accessible. All admin actions are executed successfully without permission errors.",
                "priority": "High",
            },
            {
                "objective": "Verify standard user cannot access admin-only pages",
                "description": "Security test ensuring non-admin roles are blocked from restricted sections.",
                "steps": [
                    "Log in with a standard user account (non-admin role)",
                    "Attempt to directly navigate to an admin-only URL (e.g., /admin/users)",
                    "Observe the response",
                ],
                "data": "Role: Standard User | URL: /admin/users or /admin/settings",
                "expected": "Access is denied. The user sees a 403 Forbidden error or is redirected to an 'Access Denied' page. No admin data is displayed.",
                "priority": "High",
            },
            {
                "objective": "Verify read-only user cannot modify data",
                "description": "Validates that users assigned a read-only role cannot perform create, update, or delete operations.",
                "steps": [
                    "Log in with a read-only user account",
                    "Navigate to a data entry form or record",
                    "Attempt to save/edit/delete a record",
                    "Observe whether write operations are permitted",
                ],
                "data": "Role: Read-Only | Action: edit or delete a record",
                "expected": "Edit and delete buttons are either hidden or disabled for the read-only user. Any attempt to bypass via direct API call returns HTTP 403.",
                "priority": "High",
            },
            {
                "objective": "Verify role change takes effect immediately or after the user's next login",
                "description": "Tests that updating a user's role is reflected in their access within the defined propagation time.",
                "steps": [
                    "Log in as an Admin and change a target user's role from Standard to Read-Only",
                    "Have the target user attempt an action that was previously allowed but is now restricted",
                    "Observe whether the access is correctly denied",
                ],
                "data": "User: target.user@example.com | Old Role: Standard | New Role: Read-Only",
                "expected": "After the role change (and any required session refresh), the target user cannot perform write operations. The change is reflected without requiring an application restart.",
                "priority": "Medium",
            },
        ],
    },

    # ── Form Validation ────────────────────────────────────────────────
    {
        "keywords": ["form", "validation", "input", "field", "mandatory", "required field", "submit", "data entry"],
        "label": "Forms & Validation",
        "req_id_prefix": "FORM",
        "cases": [
            {
                "objective": "Verify form submission is successful with all valid inputs",
                "description": "Happy-path test confirming the form accepts and saves all correctly entered data.",
                "steps": [
                    "Navigate to the form",
                    "Fill in all fields with valid, correctly formatted data",
                    "Click Submit",
                    "Observe the success confirmation",
                ],
                "data": "All fields: valid data matching required formats and ranges",
                "expected": "The form is submitted successfully. A confirmation message is shown and the data is persisted correctly in the system.",
                "priority": "High",
            },
            {
                "objective": "Verify required fields display validation errors when left empty",
                "description": "Tests that mandatory fields enforce completion before allowing form submission.",
                "steps": [
                    "Navigate to the form",
                    "Leave all required fields blank",
                    "Click Submit",
                    "Observe the validation messages",
                ],
                "data": "All required fields: (empty)",
                "expected": "Each required field displays an inline error. Form submission is prevented until all required fields are completed.",
                "priority": "High",
            },
            {
                "objective": "Verify numeric field rejects non-numeric input",
                "description": "Tests input type restriction for numeric form fields.",
                "steps": [
                    "Navigate to the form",
                    "Locate a field that should accept numbers only",
                    "Enter alphabetical characters or special symbols",
                    "Attempt to submit or tab away from the field",
                ],
                "data": "Numeric field input: 'abc!@#'",
                "expected": "Either the field prevents non-numeric characters from being entered, or a validation error 'Please enter a valid number' is shown.",
                "priority": "Medium",
            },
            {
                "objective": "Verify maximum character length is enforced on text fields",
                "description": "Boundary test for text input fields with a defined character limit.",
                "steps": [
                    "Navigate to the form",
                    "Enter text in a field that has a stated character limit",
                    "Enter exactly at the limit, then one character beyond the limit",
                    "Observe the field behaviour and any error messages",
                ],
                "data": "Field limit: 100 characters | Test input: 100-character string, then 101-character string",
                "expected": "At the limit (100 chars), the field accepts the input. Beyond the limit, input is either blocked or flagged with a 'Maximum X characters allowed' validation error.",
                "priority": "Medium",
            },
            {
                "objective": "Verify form data is preserved on validation failure",
                "description": "Usability test ensuring users do not lose their entered data when a validation error occurs.",
                "steps": [
                    "Navigate to the form",
                    "Fill in several fields with valid data",
                    "Leave one required field empty and submit",
                    "After the validation error appears, inspect the other fields",
                ],
                "data": "Multiple fields filled; one required field left blank",
                "expected": "Fields with valid data retain their entered values after the validation error. Only the invalid/empty field is highlighted.",
                "priority": "Medium",
            },
        ],
    },

    # ── Pagination / Listing ───────────────────────────────────────────
    {
        "keywords": ["pagination", "list", "table", "records", "page", "sort", "filter"],
        "label": "Listing & Pagination",
        "req_id_prefix": "LIST",
        "cases": [
            {
                "objective": "Verify the records list is displayed correctly with pagination controls",
                "description": "Validates the default view of a paginated list showing the correct number of records per page.",
                "steps": [
                    "Navigate to the listing/table page",
                    "Observe the default number of records displayed per page",
                    "Confirm pagination controls (Next, Previous, page numbers) are visible",
                ],
                "data": "Default page size: as configured (e.g., 10 or 25 per page)",
                "expected": "The correct number of records appears per page. Pagination controls are present and functional. The total count is accurately displayed.",
                "priority": "High",
            },
            {
                "objective": "Verify sorting by a column header works correctly",
                "description": "Tests ascending and descending sort for a column.",
                "steps": [
                    "Navigate to the listing page",
                    "Click a sortable column header (e.g., Name, Date, Status)",
                    "Observe the sort order",
                    "Click the same column header again",
                    "Observe the reversed sort order",
                ],
                "data": "Column: Name | First click: ascending | Second click: descending",
                "expected": "First click sorts the column in ascending order. Second click reverses to descending order. A sort indicator (arrow icon) reflects the current direction.",
                "priority": "Medium",
            },
            {
                "objective": "Verify the listing page shows an appropriate message when no records exist",
                "description": "Edge case test for an empty data set.",
                "steps": [
                    "Navigate to the listing page in a state where no records exist (or apply a filter that matches nothing)",
                    "Observe the page content",
                ],
                "data": "Dataset: empty (0 records)",
                "expected": "A user-friendly message such as 'No records found' is displayed. No blank table, broken layout, or error is shown.",
                "priority": "Medium",
            },
            {
                "objective": "Verify filtering the list by a specific criterion narrows results correctly",
                "description": "Tests the filter functionality to ensure only matching records are returned.",
                "steps": [
                    "Navigate to the listing page",
                    "Apply a filter (e.g., Status = Active)",
                    "Observe the filtered results",
                    "Verify all displayed records match the filter criterion",
                ],
                "data": "Filter: Status = Active",
                "expected": "Only records with Status = Active are displayed. Records with other statuses are hidden. The record count updates to reflect the filter.",
                "priority": "Medium",
            },
        ],
    },

    # ── Data Import / Export ───────────────────────────────────────────
    {
        "keywords": ["import", "export", "csv", "excel", "bulk upload", "data migration", "download"],
        "label": "Import & Export",
        "req_id_prefix": "IMPEXP",
        "cases": [
            {
                "objective": "Verify successful data import using a valid CSV file",
                "description": "Happy-path test for bulk data import via a properly formatted CSV.",
                "steps": [
                    "Navigate to the Import section",
                    "Download the template CSV to confirm the required column structure",
                    "Prepare a CSV file with valid data in the correct format",
                    "Upload the CSV",
                    "Confirm the import",
                    "Navigate to the data list and verify the imported records",
                ],
                "data": "CSV file: 50 records | All columns correctly formatted | No duplicate IDs",
                "expected": "All 50 records are imported successfully. An import summary shows the count of records processed. The data is visible in the application list.",
                "priority": "High",
            },
            {
                "objective": "Verify import rejects a CSV with missing required columns",
                "description": "Validates that the import process fails gracefully when mandatory columns are absent.",
                "steps": [
                    "Prepare a CSV file that is missing one or more required columns",
                    "Upload the file via the Import section",
                    "Observe the system response",
                ],
                "data": "CSV file with missing columns: 'Email' column removed",
                "expected": "The import is rejected. A clear error message identifies the missing columns. No partial records are created.",
                "priority": "High",
            },
            {
                "objective": "Verify data export produces a correctly formatted file with all records",
                "description": "Validates that the export function outputs all accessible records in the correct format.",
                "steps": [
                    "Navigate to the listing page",
                    "Click 'Export to CSV / Excel'",
                    "Open the downloaded file",
                    "Count the rows and verify column headers",
                ],
                "data": "Expected: all records in the system accessible to the current user",
                "expected": "The exported file contains the correct headers, all accessible records, and no data corruption or truncation.",
                "priority": "High",
            },
        ],
    },

    # ── Two-Factor Authentication / MFA ────────────────────────────────
    {
        "keywords": ["two-factor", "2fa", "mfa", "multi-factor", "otp", "one-time password", "authenticator"],
        "label": "Multi-Factor Authentication",
        "req_id_prefix": "MFA",
        "cases": [
            {
                "objective": "Verify successful login with valid OTP after entering correct password",
                "description": "End-to-end validation of the 2FA login flow.",
                "steps": [
                    "Precondition: 2FA is enabled for the user account",
                    "Navigate to the login page and enter correct username and password",
                    "When prompted for the OTP, open the authenticator app or retrieve the OTP from the registered phone",
                    "Enter the valid, current OTP",
                    "Click Verify / Submit",
                    "Observe the resulting page",
                ],
                "data": "Username: validuser@example.com | Password: Secure@123 | OTP: current 6-digit code",
                "expected": "Login is successful. The user is redirected to the home/dashboard page.",
                "priority": "High",
            },
            {
                "objective": "Verify login is rejected with an incorrect OTP",
                "description": "Validates that an expired or incorrect OTP prevents access.",
                "steps": [
                    "Complete the first factor (username + password) successfully",
                    "Enter an incorrect OTP (e.g., 000000 or an expired code)",
                    "Click Verify",
                    "Observe the system response",
                ],
                "data": "OTP: 000000 (incorrect) or a code from a previous time window",
                "expected": "Access is denied. An error message such as 'Invalid or expired verification code' is displayed. The user is prompted to try again.",
                "priority": "High",
            },
            {
                "objective": "Verify OTP expires after its valid time window",
                "description": "Security test confirming that OTP codes cannot be reused after their validity window.",
                "steps": [
                    "Generate a valid OTP",
                    "Wait until the OTP has expired (e.g., > 30 seconds for TOTP)",
                    "Attempt to use the expired code",
                    "Observe the response",
                ],
                "data": "OTP: valid code used after expiry window",
                "expected": "The expired OTP is rejected. The user is prompted to generate a new code.",
                "priority": "High",
            },
        ],
    },

    # ── Session Management / Logout ────────────────────────────────────
    {
        "keywords": ["session", "logout", "sign out", "timeout", "session expiry", "idle"],
        "label": "Session Management",
        "req_id_prefix": "SESS",
        "cases": [
            {
                "objective": "Verify user is successfully logged out after clicking Logout",
                "description": "Validates the logout workflow and ensures the session is fully terminated.",
                "steps": [
                    "Log in with valid credentials",
                    "Click the Logout / Sign Out button",
                    "Attempt to navigate back to a protected page using the browser Back button",
                    "Also attempt to access a protected page directly by URL",
                ],
                "data": "N/A",
                "expected": "The session is terminated. The user is redirected to the login page. Pressing Back or directly navigating to a protected page also redirects to login. The session token/cookie is invalidated.",
                "priority": "High",
            },
            {
                "objective": "Verify session expires after the configured idle timeout period",
                "description": "Tests the automatic session expiration for inactive users.",
                "steps": [
                    "Precondition: Session idle timeout is configured (e.g., 15 minutes)",
                    "Log in with valid credentials",
                    "Leave the application idle for longer than the configured timeout period",
                    "Attempt to interact with the application",
                ],
                "data": "Idle period: greater than configured timeout (e.g., > 15 minutes)",
                "expected": "The user is automatically logged out. On attempting to interact, they are redirected to the login page with a message such as 'Your session has expired. Please log in again.'",
                "priority": "High",
            },
            {
                "objective": "Verify that navigating to protected pages without a valid session redirects to login",
                "description": "Security check ensuring that protected routes are inaccessible without authentication.",
                "steps": [
                    "Open a private/incognito browser window (no active session)",
                    "Attempt to navigate directly to a protected URL (e.g., /dashboard, /profile)",
                    "Observe the result",
                ],
                "data": "Protected URL: /dashboard (or equivalent) | Session: None",
                "expected": "The user is redirected to the login page. No protected data is served. HTTP response code is 302 (redirect) or 401 (unauthorized).",
                "priority": "High",
            },
        ],
    },

    # ── Responsive / Mobile UI ─────────────────────────────────────────
    {
        "keywords": ["responsive", "mobile", "tablet", "screen size", "viewport", "ui", "layout", "browser"],
        "label": "UI & Accessibility",
        "req_id_prefix": "UI",
        "cases": [
            {
                "objective": "Verify the application layout is fully functional on mobile viewport (320px–480px)",
                "description": "Validates that all key UI components render correctly and are usable on small mobile screen widths.",
                "steps": [
                    "Open the application in a browser's developer tools",
                    "Set the viewport to 375px × 667px (iPhone SE simulation)",
                    "Navigate through all key pages",
                    "Interact with forms, buttons, and navigation",
                ],
                "data": "Viewport: 375×667 (mobile) | Browser: Chrome/Safari",
                "expected": "No horizontal scrollbar appears. All text is legible. Buttons are large enough to tap. Navigation collapses to a hamburger menu or equivalent. Forms are fully usable.",
                "priority": "High",
            },
            {
                "objective": "Verify the application renders correctly across supported desktop browsers",
                "description": "Cross-browser compatibility test for the latest versions of major browsers.",
                "steps": [
                    "Open the application in Chrome, Firefox, Edge, and Safari",
                    "Navigate all key pages in each browser",
                    "Compare rendering, functionality, and styles",
                ],
                "data": "Browsers: Chrome (latest), Firefox (latest), Edge (latest), Safari (latest) | Viewport: 1280×800",
                "expected": "Layout, styles, and functionality are consistent across all tested browsers. No browser-specific CSS or JavaScript errors occur.",
                "priority": "Medium",
            },
            {
                "objective": "Verify keyboard navigation and accessibility (a11y) compliance",
                "description": "Accessibility test ensuring the application can be fully navigated using the keyboard alone and meets basic WCAG criteria.",
                "steps": [
                    "Open the application",
                    "Use only the Tab key to navigate through all interactive elements",
                    "Use Enter/Space to activate buttons and links",
                    "Use an accessibility audit tool (e.g., Axe, Lighthouse) to check for violations",
                ],
                "data": "Navigation method: keyboard only | Audit tool: Axe or equivalent",
                "expected": "All interactive elements are reachable via Tab. Focus order is logical. Focus is visually indicated. Axe/Lighthouse reports zero critical violations.",
                "priority": "Medium",
            },
        ],
    },

    # ── Delete / Remove ────────────────────────────────────────────────
    {
        "keywords": ["delete", "remove", "archive", "deactivate", "soft delete", "hard delete"],
        "label": "Delete & Archive",
        "req_id_prefix": "DEL",
        "cases": [
            {
                "objective": "Verify authorised user can delete a record with confirmation",
                "description": "Happy-path test for the delete workflow including the confirmation dialog.",
                "steps": [
                    "Log in as a user with delete permission",
                    "Navigate to the record list",
                    "Select a record and click Delete",
                    "When the confirmation dialog appears, confirm the deletion",
                    "Observe the result",
                ],
                "data": "Record to delete: an existing, non-critical test record",
                "expected": "The record is deleted (or soft-deleted/archived). It no longer appears in the active list. A success notification is shown.",
                "priority": "High",
            },
            {
                "objective": "Verify deletion is cancelled when the user dismisses the confirmation dialog",
                "description": "Tests that the record is preserved when the delete action is aborted.",
                "steps": [
                    "Initiate the delete action on a record",
                    "When the confirmation dialog appears, click Cancel",
                    "Verify the record still exists",
                ],
                "data": "Confirmation dialog: Cancel clicked",
                "expected": "The record is not deleted. It remains in the list unchanged.",
                "priority": "Medium",
            },
            {
                "objective": "Verify unauthorised user cannot delete records",
                "description": "Permission control test ensuring delete operations are restricted to authorised roles.",
                "steps": [
                    "Log in as a user without delete permission (e.g., Read-Only role)",
                    "Navigate to the records list",
                    "Observe whether a Delete button/option is available",
                    "If available, attempt to use it",
                    "Also attempt to send a DELETE request directly via API",
                ],
                "data": "User Role: Read-Only | Action: delete a record",
                "expected": "The Delete option is hidden or disabled in the UI. A direct API DELETE request returns HTTP 403 Forbidden.",
                "priority": "High",
            },
        ],
    },

    # ── Audit Logging ──────────────────────────────────────────────────
    {
        "keywords": ["audit", "audit log", "activity log", "log", "history", "trail", "tracking"],
        "label": "Audit & Logging",
        "req_id_prefix": "AUDIT",
        "cases": [
            {
                "objective": "Verify significant user actions are captured in the audit log",
                "description": "Validates that critical operations (login, data change, delete) generate corresponding audit log entries.",
                "steps": [
                    "Perform a significant action (e.g., update a record, change a user's role, delete a record)",
                    "Navigate to the Audit Log section",
                    "Search or filter for the recent action",
                    "Inspect the log entry",
                ],
                "data": "Action: Update record ID 42 | User: admin@example.com",
                "expected": "An audit log entry is created containing: timestamp, user identity, action type, affected resource ID, and before/after values (if applicable).",
                "priority": "High",
            },
            {
                "objective": "Verify audit logs cannot be modified or deleted by standard users",
                "description": "Security test ensuring audit log immutability.",
                "steps": [
                    "Log in as a standard user",
                    "Navigate to the audit log page (if accessible)",
                    "Attempt to edit or delete an audit log entry",
                    "Also attempt direct database-level access via the UI",
                ],
                "data": "User Role: Standard | Action: attempt to delete/edit audit entries",
                "expected": "No edit or delete options are available in the audit log UI. Direct manipulation attempts return permission errors.",
                "priority": "High",
            },
        ],
    },
]

# ---------------------------------------------------------------------------
# Requirement-text parsing – produces cases tailored to whatever the user
# actually typed, even when no domain rule (login, payment, etc.) matches.
# This is what keeps output "professional" for topics outside the 19
# hard-coded domains instead of falling straight to generic boilerplate.
# ---------------------------------------------------------------------------

_ACTION_KEYWORDS = [
    "should", "must", "shall", "can", "cannot", "can't", "allow", "allows",
    "enable", "enables", "require", "requires", "validate", "validates",
    "restrict", "restricts", "limit", "limits", "display", "displays",
    "show", "shows", "prevent", "prevents", "support", "supports",
    "ensure", "ensures", "provide", "provides", "block", "blocks",
    "reject", "rejects", "accept", "accepts", "generate", "generates",
    "send", "sends", "update", "updates", "delete", "deletes", "create",
    "creates", "calculate", "calculates", "notify", "notifies", "trigger",
    "triggers", "redirect", "redirects", "store", "stores", "retrieve",
    "retrieves", "filter", "filters", "sort", "sorts", "export", "exports",
    "import", "imports", "convert", "converts", "process", "processes",
]

_NEGATION_KEYWORDS = ["not", "cannot", "can't", "never", "only", "must not",
                      "should not", "restrict", "limit", "block", "prevent",
                      "reject", "no more than", "at most", "maximum", "minimum"]

_NUMBER_RE = re.compile(
    r"\b\d+(?:\.\d+)?\s*"
    r"(?:%|percent|characters?|chars?|digits?|mb|kb|gb|seconds?|secs?|ms|"
    r"minutes?|mins?|hours?|hrs?|days?|items?|rows?|records?|attempts?|"
    r"users?|times?)?\b",
    re.IGNORECASE,
)


def _split_requirement_statements(text: str) -> List[str]:
    """Break free-text requirement details into individual actionable statements."""
    if not text:
        return []
    # Split on newlines/bullets first, then on sentence boundaries.
    rough = re.split(r"[\n\r]+", text)
    statements: List[str] = []
    for chunk in rough:
        for piece in re.split(r"(?<=[.;])\s+", chunk):
            cleaned = re.sub(r"^[\s\-\*\u2022\d]+[\.\)]?\s*", "", piece).strip().rstrip(".")
            if len(cleaned) >= 8:
                statements.append(cleaned)
    return statements


def _statement_has_action(statement: str) -> bool:
    return _any_kw(statement, _ACTION_KEYWORDS)


def _statement_has_constraint(statement: str) -> bool:
    sl = statement.lower()
    return any(kw in sl for kw in _NEGATION_KEYWORDS) or bool(_NUMBER_RE.search(statement))


def _lower_first(s: str) -> str:
    return s[:1].lower() + s[1:] if s else s


def _derive_cases_from_requirement(req_name: str, requirements: str) -> List[Dict]:
    """
    Build test cases directly from the sentences the user actually wrote,
    so that requirements outside the pre-built domain list (login, payment,
    file-upload, etc.) still get specific, presentable test cases instead
    of generic placeholder text.
    """
    statements = _split_requirement_statements(requirements)
    derived: List[Dict] = []

    for idx, statement in enumerate(statements, start=1):
        if not _statement_has_action(statement) and len(statement) < 15:
            continue

        readable = _lower_first(statement)

        # ---- Positive case: the stated behaviour happens as described ----
        derived.append({
            "objective": f"Verify: {statement}",
            "description": (
                f"Validates the specific requirement statement for '{req_name}': "
                f"\"{statement}\". Confirms the system behaves exactly as specified "
                f"under normal, valid conditions."
            ),
            "steps": [
                f"Precondition: The application is set up and accessible for the '{req_name}' feature",
                f"Navigate to the part of the application that implements: {readable}",
                "Set up valid data/inputs required to exercise this behaviour",
                "Perform the action described in the requirement statement",
                "Observe and record the actual system behaviour",
            ],
            "data": "Valid input consistent with the stated requirement",
            "expected": (
                f"The system behaves exactly as specified: \"{statement}\". "
                f"No errors, exceptions, or deviations occur."
            ),
            "priority": "High",
        })

        # ---- Negative / constraint case, only where the statement implies
        #      a rule, limit, or restriction worth breaking on purpose ----
        if _statement_has_constraint(statement):
            numbers = _NUMBER_RE.findall(statement)
            data_hint = (
                f"Boundary/violating value near: {', '.join(n.strip() for n in numbers)}"
                if numbers else "Input that intentionally violates the stated rule"
            )
            derived.append({
                "objective": f"Verify enforcement of constraint: {statement}",
                "description": (
                    f"Negative/boundary test for '{req_name}' targeting the constraint: "
                    f"\"{statement}\". Confirms the system correctly rejects or handles "
                    f"attempts that violate this rule."
                ),
                "steps": [
                    f"Precondition: The application is set up for the '{req_name}' feature",
                    f"Navigate to the relevant screen/action for: {readable}",
                    "Attempt the action using input that deliberately violates the stated constraint "
                    "(e.g., a value just past any stated limit, or the disallowed condition itself)",
                    "Submit / trigger the action",
                    "Observe the system's validation and error-handling response",
                ],
                "data": data_hint,
                "expected": (
                    f"The system correctly enforces the rule (\"{statement}\"): the invalid attempt "
                    f"is rejected with a clear, specific error message, and no invalid state is persisted."
                ),
                "priority": "High",
            })

        if idx >= 8:  # cap so very long requirement text doesn't explode into 40+ cases
            break

    return derived


# ---------------------------------------------------------------------------
# Generic test cases – used when no domain rule matches
# ---------------------------------------------------------------------------

_GENERIC_POSITIVE = [
    {
        "objective": "Verify the primary happy-path workflow executes successfully",
        "description": "Validates the end-to-end positive scenario where a user performs the core action described in the requirement with all valid inputs and preconditions met.",
        "steps": [
            "Precondition: All required data and system state are set up correctly",
            "Authenticate as a user with appropriate access rights",
            "Navigate to the relevant section of the application",
            "Perform the primary action described in the requirement using valid inputs",
            "Confirm the action by clicking Save / Submit / Confirm",
            "Observe the system response",
        ],
        "data": "Valid inputs as specified in the requirement",
        "expected": "The action completes successfully. A confirmation message is displayed. The system state is updated as per the requirement specification.",
        "priority": "High",
    },
    {
        "objective": "Verify the feature is accessible to authorised users",
        "description": "Validates that users with the required roles/permissions can access the feature without encountering access errors.",
        "steps": [
            "Log in with a user account that has the required role",
            "Navigate to the feature in question",
            "Verify the page or component loads correctly",
            "Confirm all relevant UI elements are visible and interactive",
        ],
        "data": "User Role: Authorised role as per requirement",
        "expected": "The feature loads without errors. All expected UI elements are present. No permission error is displayed.",
        "priority": "High",
    },
    {
        "objective": "Verify all required fields/elements render correctly on initial load",
        "description": "UI render test ensuring the page or form displays all required elements in the correct state when first loaded.",
        "steps": [
            "Navigate to the relevant page or feature",
            "Inspect the page without performing any actions",
            "Verify all required fields, labels, buttons, and controls are present",
        ],
        "data": "N/A — observational test",
        "expected": "All required UI elements are displayed. Labels are accurate. Default values (if any) are correct. No console errors are logged.",
        "priority": "Medium",
    },
]

_GENERIC_NEGATIVE = [
    {
        "objective": "Verify graceful error handling when invalid input is submitted",
        "description": "Tests the system's response to deliberately malformed or out-of-range input data.",
        "steps": [
            "Navigate to the relevant input form or feature",
            "Enter invalid, malformed, or out-of-range data in one or more fields",
            "Attempt to submit or trigger the action",
            "Observe the error handling behaviour",
        ],
        "data": "Invalid inputs: empty required fields, wrong data types, out-of-range values, special characters",
        "expected": "The system displays clear, user-friendly validation error messages. The invalid data is not persisted. The application remains in a stable state.",
        "priority": "High",
    },
    {
        "objective": "Verify the feature is inaccessible to unauthorised users",
        "description": "Access control test ensuring users without the necessary permissions cannot use the feature.",
        "steps": [
            "Log in with an account that lacks the necessary permission",
            "Attempt to navigate to the feature",
            "Observe the system response",
        ],
        "data": "User Role: Insufficient/unauthorised role",
        "expected": "Access is denied. The user sees an Access Denied page or is redirected to login. No sensitive data is exposed.",
        "priority": "High",
    },
    {
        "objective": "Verify system behaviour when a required backend service or dependency is unavailable",
        "description": "Resilience test checking the application's response to dependency failures.",
        "steps": [
            "Precondition: Simulate or configure a backend service outage (database, API, cache)",
            "Perform the action that depends on the unavailable service",
            "Observe the UI response and any error messages",
        ],
        "data": "Simulated dependency: database/API unavailable",
        "expected": "The application displays a meaningful error message (e.g., 'Service temporarily unavailable. Please try again.'). No stack trace or internal error details are exposed to the end user.",
        "priority": "High",
    },
]

_GENERIC_BOUNDARY = [
    {
        "objective": "Verify behaviour at the minimum allowed input boundary value",
        "description": "Boundary value analysis test for the lower limit of an input field or parameter.",
        "steps": [
            "Navigate to the relevant input",
            "Enter the exact minimum allowed value as defined in the requirement",
            "Submit the input",
            "Observe the result",
        ],
        "data": "Input: minimum allowed value (as per specification)",
        "expected": "The minimum boundary value is accepted and processed correctly. No validation error is triggered.",
        "priority": "Medium",
    },
    {
        "objective": "Verify behaviour at the maximum allowed input boundary value",
        "description": "Boundary value analysis test for the upper limit.",
        "steps": [
            "Navigate to the relevant input",
            "Enter the exact maximum allowed value as defined in the requirement",
            "Submit the input",
            "Observe the result",
        ],
        "data": "Input: maximum allowed value (as per specification)",
        "expected": "The maximum boundary value is accepted and processed correctly. No validation error is triggered.",
        "priority": "Medium",
    },
    {
        "objective": "Verify that a value just below the minimum boundary is rejected",
        "description": "Off-by-one boundary test for the lower limit.",
        "steps": [
            "Navigate to the relevant input",
            "Enter a value that is one unit below the minimum allowed value",
            "Submit and observe the result",
        ],
        "data": "Input: (minimum allowed value) − 1",
        "expected": "The below-minimum value is rejected. A validation error message is displayed.",
        "priority": "Medium",
    },
    {
        "objective": "Verify that a value just above the maximum boundary is rejected",
        "description": "Off-by-one boundary test for the upper limit.",
        "steps": [
            "Navigate to the relevant input",
            "Enter a value that is one unit above the maximum allowed value",
            "Submit and observe the result",
        ],
        "data": "Input: (maximum allowed value) + 1",
        "expected": "The above-maximum value is rejected. A validation error message is displayed.",
        "priority": "Medium",
    },
]

_GENERIC_SECURITY = [
    {
        "objective": "Verify the feature is protected against SQL injection attempts",
        "description": "Security test injecting SQL metacharacters to confirm the application uses parameterised queries.",
        "steps": [
            "Navigate to any text input or search field associated with the feature",
            "Enter a SQL injection payload in the input",
            "Submit",
            "Inspect the response for SQL errors or unintended data exposure",
        ],
        "data": "Injection payload: ' OR '1'='1'; DROP TABLE users;-- | 1' OR 1=1 LIMIT 1--",
        "expected": "The payload is treated as literal text. No SQL error is shown. No unintended records are returned. The application remains stable.",
        "priority": "High",
    },
    {
        "objective": "Verify the feature is protected against Cross-Site Scripting (XSS)",
        "description": "Security test checking that user-supplied data is properly encoded before being rendered in the browser.",
        "steps": [
            "Navigate to any input field that displays user-supplied content",
            "Enter an XSS payload in the input",
            "Save and then navigate to the page that renders the stored value",
            "Observe whether the script executes",
        ],
        "data": "XSS payload: <script>alert('XSS')</script> | <img src=x onerror=alert(1)>",
        "expected": "The script is not executed. The payload is escaped and displayed as plain text. No alert dialog appears.",
        "priority": "High",
    },
]

_GENERIC_PERF = [
    {
        "objective": "Verify the feature responds within the defined performance SLA under normal load",
        "description": "Basic performance smoke test measuring page/feature load time under a single user.",
        "steps": [
            "Navigate to the feature with a standard dataset",
            "Measure the time from initiating the action to the page/result being fully rendered",
            "Repeat 5 times and calculate the average",
        ],
        "data": "Standard dataset (as per typical production load) | Single concurrent user",
        "expected": "Average response time is within the defined SLA (e.g., < 3 seconds). No timeout or partial-render occurs.",
        "priority": "Medium",
    },
    {
        "objective": "Verify feature performance degrades gracefully under high concurrent load",
        "description": "Simulates multiple concurrent users to confirm the system remains stable and within acceptable thresholds.",
        "steps": [
            "Configure a load testing tool to simulate 50 concurrent users",
            "Execute the primary feature action simultaneously",
            "Monitor response times, error rates, and server resource usage",
            "Increase to 100 concurrent users and repeat monitoring",
        ],
        "data": "50 and 100 concurrent users | Load testing tool (e.g., JMeter, k6)",
        "expected": "Response time stays below 5 seconds at 50 users. Error rate remains below 1%. System does not crash or return 5xx errors at 100 users.",
        "priority": "Medium",
    },
    {
        "objective": "Verify the system recovers gracefully after a transient failure",
        "description": "Tests that the system automatically recovers or displays a helpful message when a downstream dependency is temporarily unavailable.",
        "steps": [
            "Simulate a transient failure in a dependent service (e.g., database timeout)",
            "Attempt to use the feature during the failure window",
            "Restore the dependent service",
            "Attempt to use the feature again after recovery",
        ],
        "data": "Simulated downstream failure | Recovery interval: 30 seconds",
        "expected": "During failure: user sees a graceful error message, not a raw exception. After recovery: feature works normally with no data loss.",
        "priority": "High",
    },
]

_GENERIC_USABILITY = [
    {
        "objective": "Verify all user-facing messages are clear, professional, and free of technical jargon",
        "description": "Usability review of system-generated messages including success confirmations, validation errors, and system alerts.",
        "steps": [
            "Perform various actions that trigger system messages (submit form, trigger error, complete workflow)",
            "Review every displayed message",
        ],
        "data": "All triggered user-facing messages",
        "expected": "Messages are concise, written in plain language, and provide actionable guidance. No raw exception messages or internal codes are exposed.",
        "priority": "Low",
    },
    {
        "objective": "Verify the application state is consistent when navigating away and returning mid-workflow",
        "description": "Tests that partial workflow state is handled gracefully if the user navigates away and returns.",
        "steps": [
            "Begin a multi-step workflow (e.g., a multi-page form)",
            "Partway through, navigate away to a different page",
            "Return to the workflow page",
            "Observe the state",
        ],
        "data": "Multi-step workflow partially completed",
        "expected": "Either the entered data is preserved (draft state) or the user is clearly informed they will lose unsaved progress. No data corruption occurs.",
        "priority": "Low",
    },
    {
        "objective": "Verify the UI is fully accessible via keyboard navigation",
        "description": "Confirms all interactive elements can be reached and activated using only a keyboard, supporting users with mobility impairments.",
        "steps": [
            "Open the feature page",
            "Use Tab to navigate through all interactive elements",
            "Use Enter/Space to activate buttons, links, and checkboxes",
            "Verify focus indicators are visible at every step",
        ],
        "data": "No mouse input; keyboard only (Tab, Shift+Tab, Enter, Space, Arrow keys)",
        "expected": "Every interactive element is reachable by keyboard. Focus order is logical. Actions fire correctly via keyboard. No focus traps exist.",
        "priority": "Medium",
    },
    {
        "objective": "Verify the application renders correctly on mobile screen sizes",
        "description": "Responsive design test to confirm the feature is usable on small screens without horizontal scrolling or overlapping elements.",
        "steps": [
            "Open the application in a browser",
            "Enable DevTools responsive mode and set viewport to 375×812 (iPhone SE)",
            "Navigate to the feature",
            "Interact with all key UI elements",
        ],
        "data": "Viewport: 375×812 px | Device: iPhone SE / small Android",
        "expected": "Layout reflows correctly. No horizontal overflow. Text is readable. Buttons and inputs are tap-friendly (min 44×44 px). No elements overlap.",
        "priority": "Medium",
    },
    {
        "objective": "Verify confirmation dialogs prevent accidental destructive actions",
        "description": "Ensures that irreversible actions (delete, reset, submit) are guarded by a confirmation prompt to prevent unintentional data loss.",
        "steps": [
            "Locate a destructive action button (e.g., Delete, Reset, Submit)",
            "Click the button",
            "Observe whether a confirmation prompt appears",
            "Click Cancel and verify no action was taken",
            "Click the button again, confirm, and verify the action completes",
        ],
        "data": "Destructive action: Delete / Reset / Submit",
        "expected": "Confirmation dialog appears. Cancelling aborts the action with no changes. Confirming executes the action and displays appropriate success feedback.",
        "priority": "Medium",
    },
]

_GENERIC_INTEGRATION = [
    {
        "objective": "Verify the feature integrates correctly with external data sources",
        "description": "Checks that data retrieved from or sent to an external system (API, database, third-party service) is accurate and complete.",
        "steps": [
            "Configure the integration endpoint (staging/mock)",
            "Trigger the feature action that reads from or writes to the external source",
            "Cross-check the data returned / sent against expected values",
        ],
        "data": "Integration endpoint: staging | Expected payload: as per API contract",
        "expected": "Data matches the expected contract. No data is dropped, truncated, or transformed incorrectly. HTTP status 200/201 returned.",
        "priority": "High",
    },
    {
        "objective": "Verify the feature handles external service timeouts gracefully",
        "description": "Simulates a slow or non-responsive external dependency to confirm the system does not hang indefinitely.",
        "steps": [
            "Configure the external dependency to delay response beyond the timeout threshold",
            "Trigger the feature that calls the external service",
            "Observe system behaviour after the timeout window elapses",
        ],
        "data": "Simulated delay: > configured timeout (e.g., 30 seconds)",
        "expected": "The system times out after the configured period, displays a user-friendly error, and does not leave the user in an indefinite loading state.",
        "priority": "High",
    },
    {
        "objective": "Verify data consistency across modules after a cross-module update",
        "description": "Ensures that when one module modifies shared data, all other dependent modules reflect the change in real time or after a defined sync window.",
        "steps": [
            "Perform an update action in Module A that affects shared data",
            "Navigate to Module B which displays the same data",
            "Observe whether Module B reflects the updated value",
        ],
        "data": "Cross-module shared record updated in Module A",
        "expected": "Module B displays the updated value within the defined sync window. No stale data or caching artefact is shown.",
        "priority": "Medium",
    },
]

_GENERIC_REGRESSION = [
    {
        "objective": "Verify previously reported defects do not recur after a new release",
        "description": "Re-executes test scenarios for known historical bugs to ensure they have not been reintroduced.",
        "steps": [
            "Retrieve the list of closed defects related to this feature",
            "Re-execute each defect reproduction scenario",
            "Observe whether the defect manifests",
        ],
        "data": "Defect list from previous release | Bug IDs as per project tracker",
        "expected": "None of the historical defects reproduce. Each scenario completes with the expected, fixed behaviour.",
        "priority": "High",
    },
    {
        "objective": "Verify the feature works correctly after a database schema migration",
        "description": "Confirms that a database upgrade or migration has not broken existing functionality or corrupted existing data.",
        "steps": [
            "Apply the database migration script to the test environment",
            "Execute the full feature smoke test suite",
            "Query the database directly to verify data integrity post-migration",
        ],
        "data": "Migration script version: latest | Existing data set: pre-migration snapshot",
        "expected": "All smoke tests pass. Existing data is intact and correctly mapped to the new schema. No orphaned or missing records.",
        "priority": "High",
    },
]

# ---------------------------------------------------------------------------
# Main generator function
# ---------------------------------------------------------------------------

def _ai_generate_test_cases(req_name: str, requirements: str) -> List[Dict[str, Any]]:
    """
    Call the Anthropic API to generate unique, industry-standard test cases
    for the given requirement. Returns a list of test case dicts matching COLUMNS.
    Raises an exception if the API call fails or the response cannot be parsed.
    """
    import os, json, re as _re

    try:
        import anthropic
    except ImportError:
        raise RuntimeError(
            "The 'anthropic' package is not installed. "
            "Run: pip install anthropic"
        )

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")

    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""You are a senior QA engineer with 10+ years of experience on live enterprise projects.

Generate a comprehensive set of test cases for the following software requirement.
The test cases must be:
- Unique and non-repetitive
- Industry-standard and based on real-world live project scenarios
- Directly and specifically relevant to this exact requirement
- Covering: positive flows, negative/invalid inputs, boundary values,
  validation, security probes, edge cases, and performance hints where relevant

REQUIREMENT NAME: {req_name}
REQUIREMENT DETAILS: {requirements}

Return ONLY a JSON array (no markdown, no explanation, no code fences).
Each element must have these exact keys:
{{
  "sl_no": <integer>,
  "tc_id": <string like "TC-001">,
  "tc_objective": <string>,
  "tc_description": <string>,
  "tc_steps": <string, numbered steps each on its own line>,
  "test_data": <string>,
  "expected_output": <string>,
  "requirement_id": <string like "REQ-001">,
  "priority": <"High" | "Medium" | "Low">,
  "status": "Not Executed",
  "pass_fail": "N/A"
}}

Generate at least 10 test cases. Each must be specific to "{req_name}" —
no generic placeholders. Use realistic test data relevant to the domain."""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = "".join(
        block.text for block in message.content if hasattr(block, "text")
    )

    # Strip possible ```json fences
    clean = _re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=_re.IGNORECASE)
    clean = _re.sub(r"\s*```\s*$", "", clean)

    cases = json.loads(clean)

    result: List[Dict[str, Any]] = []
    for i, c in enumerate(cases, start=1):
        steps_raw = c.get("tc_steps", "")
        # Ensure steps are newline-separated strings (already numbered by the model)
        steps_list = [s.strip() for s in steps_raw.split("\n") if s.strip()]

        result.append(
            _make_case(
                sl=i,
                tc_id=f"TC-{i:03d}",
                objective=c.get("tc_objective", ""),
                description=c.get("tc_description", ""),
                steps=steps_list,
                test_data=c.get("test_data", "N/A"),
                expected=c.get("expected_output", ""),
                req_id=c.get("requirement_id", f"REQ-{i:03d}"),
                priority=c.get("priority", "Medium"),
            )
        )

    return result


def _rule_generate_test_cases(req_name: str, requirements: str) -> List[Dict[str, Any]]:
    """
    Fallback: keyword-rule based test case generation (original v5 logic).
    """
    combined_text = f"{req_name} {requirements}"

    matched_cases: List[Dict] = []
    used_prefixes: List[str] = []
    seen_objectives: set = set()

    for rule in _DOMAIN_RULES:
        if _any_kw(combined_text, rule["keywords"]):
            prefix = rule["req_id_prefix"]
            domain_label = rule.get("label", prefix)
            used_prefixes.append(prefix)
            for c in rule["cases"]:
                obj = c["objective"]
                if obj not in seen_objectives:
                    matched_cases.append({**c, "_prefix": prefix, "_group": domain_label})
                    seen_objectives.add(obj)

    # Derive cases directly from the requirement text itself. This covers
    # topics that aren't one of the hard-coded domains above, so output
    # stays specific/professional instead of falling straight to generic
    # placeholder text.
    req_prefix = re.sub(r"[^A-Z0-9]", "", req_name.upper())[:6] or "REQ"
    for c in _derive_cases_from_requirement(req_name, requirements):
        obj = c["objective"]
        if obj not in seen_objectives:
            matched_cases.append({**c, "_prefix": req_prefix, "_group": req_name})
            seen_objectives.add(obj)

    generic_pool = (
        _GENERIC_POSITIVE
        + _GENERIC_NEGATIVE
        + _GENERIC_BOUNDARY
        + _GENERIC_SECURITY
        + _GENERIC_PERF
        + _GENERIC_USABILITY
        + _GENERIC_INTEGRATION
        + _GENERIC_REGRESSION
    )

    # Only pad with fully generic boilerplate if the domain rules + the
    # requirement-derived cases above didn't already produce solid coverage.
    MIN_CASES_BEFORE_GENERIC_PADDING = 8
    if len(matched_cases) < MIN_CASES_BEFORE_GENERIC_PADDING:
        for c in generic_pool:
            obj = c["objective"]
            if obj not in seen_objectives:
                matched_cases.append({**c, "_prefix": "GEN", "_group": "General"})
                seen_objectives.add(obj)
            if len(matched_cases) >= MIN_CASES_BEFORE_GENERIC_PADDING:
                break

    prefix_counters: Dict[str, int] = {}
    final_prefix = used_prefixes[0] if used_prefixes else "REQ"

    result: List[Dict[str, Any]] = []
    for sl, c in enumerate(matched_cases, start=1):
        pfx = c.get("_prefix", final_prefix)
        prefix_counters[pfx] = prefix_counters.get(pfx, 0) + 1
        req_id = f"{pfx}-{prefix_counters[pfx]:03d}"
        tc_id = f"TC-{sl:03d}"

        base_desc = c.get("description", "")
        description = f"Requirement: '{req_name}'. " + base_desc

        result.append(
            {
                **_make_case(
                    sl=sl,
                    tc_id=tc_id,
                    objective=c["objective"],
                    description=description,
                    steps=c["steps"],
                    test_data=c.get("data", "N/A"),
                    expected=c["expected"],
                    req_id=req_id,
                    priority=c.get("priority", "Medium"),
                ),
                "_group": c.get("_group", final_prefix),
            }
        )

    return result


def generate_test_cases(
    req_name: str,
    requirements: str,
) -> List[Dict[str, Any]]:
    """
    Generate a comprehensive, requirement-specific set of test cases.

    Strategy
    --------
    1. If ANTHROPIC_API_KEY is set, call the Claude API for unique,
       real-world, AI-generated test cases tailored to this requirement.
    2. If the API key is missing or the call fails, fall back to the
       built-in keyword-rule engine (original v5 logic).

    Parameters
    ----------
    req_name : str
        Short name of the requirement.
    requirements : str
        Detailed requirement description.

    Returns
    -------
    List[Dict[str, Any]]
        List of test case dicts matching COLUMNS.
    """
    import os

    fallback_reason = None

    if os.getenv("ANTHROPIC_API_KEY", "").strip():
        try:
            cases = _ai_generate_test_cases(req_name, requirements)
            for c in cases:
                c["_generation_source"] = "ai"
            return cases
        except Exception as exc:
            # Log to stderr for the operator, and also surface a short
            # reason on the returned cases so the UI can tell the user
            # *why* they're seeing rule-engine output instead of AI output.
            import sys
            fallback_reason = str(exc)
            print(
                f"[test_generator] AI generation failed for '{req_name}': {exc}. "
                "Falling back to rule-based engine.",
                file=sys.stderr,
            )
    else:
        fallback_reason = "ANTHROPIC_API_KEY is not set"

    cases = _rule_generate_test_cases(req_name, requirements)
    for c in cases:
        c["_generation_source"] = "rules"
        c["_fallback_reason"] = fallback_reason
    return cases

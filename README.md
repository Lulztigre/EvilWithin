# EvilWithin
This backend utility is designed to dynamically intercept and hook a target JavaScript function at runtime to extract symmetric encryption keys (e.g., RSA, OpenSSL, AES) utilized by the application for encrypting and decrypting HTTP request and response bodies.
- Target Function (HOOK_JS): Specify the exact JavaScript function responsible for cryptographic operations. This is the entry point for instrumentation.
- Runtime Hooking: The tool injects hooks into the JavaScript execution context, enabling real-time observation and extraction of cryptographic material.
- Key Extraction: Once hooked, the tool captures symmetric keys during invocation, allowing analysis of the encryption scheme.
- Algorithm Awareness: The implementation is intentionally generic, but understanding the specific encryption algorithm in use may require manual inspection and code adaptation.
- Expertise Required: This is not a plug-and-play solution. Familiarity with JavaScript internals, browser debugging, and cryptographic workflows is essential to effectively utilize and adapt the tool.

USAGE
==================================================================================================
python ./HypedRabbit.py url --timeout 3600

- interact with the broswer then it dumps the IV, SECRET in plain text.
- increase the browser duration if you'll be testing the application extensively.

- <img width="1697" height="462" alt="image" src="https://github.com/user-attachments/assets/23e966a4-1cff-488b-827c-5c082e47c17a" />

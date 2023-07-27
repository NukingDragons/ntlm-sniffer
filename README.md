# NTLM Sniffer

This tool/library will passively collect NetNTLM hashes from unencrypted SMBv1, SMBv2, and HTTP traffic.

# Building

Running `make` by itself will create the following 4 binaries:

 - ntlm-sniffer
 - ntlm-sniffer-static
 - libntlmsniffer.so
 - libntlmsniffer.a

By default, the library will build with linux raw-socket support. To compile the library without this support, issue the command `make raw`.

# Usage

Both of the binaries need to be ran with root privileges in order to create the raw socket. The help menu can be seen by running `./ntlm-sniffer -h`. By default, the command will dump the hashes into stdout. Otherwise, with the `-o` option, it will attempt to output into a file.

# Library

If using the linux support version of the library, the following commands are available (and exclusive) to this version:

In `utils.h`:

```c
int32_t open_raw_socket(int32_t *mtu);
int8_t apply_bpf(int32_t sock, struct sock_filter *filter, uint64_t filter_size);
```

- open_raw_socket
  - Creates a raw socket and outputs the *optional* mtu into the provided first parameter. Pass in by reference.
  - Returns a socket, or on error a less-than-zero value.
- apply_bpf
  - Applies a BPF to a socket. This function is optional when using the handle_ntlmssp function below.
  - Returns 0 on success, or on error a less-than-zero value.

In `ntlmssp.h`:

```c
// Callback type
typedef int8_t (*ntlmssp_callback_t)(struct netntlm_t *netntlm, void *args);

// Pre-made BPF
extern struct sock_filter ntlmssp_bpf[];

int8_t handle_ntlmssp(int32_t sock, int32_t mtu, uint8_t use_bpf, uint64_t stack_timeout, ntlmssp_callback_t callback, void *callback_args);
```

- handle_ntlmssp
  - Set use_bpf to a non-zero value to apply the built-in ntlmssp_bpf variable to the socket. Alternatively, use the apply_bpf function with the global ntlmssp_bpf variable, or any other bpf you specify.
  - Set stack_timeout to the amount of time any unresolved packet is allowed to live in memory, set to 0 to disable (NOT RECOMMENDED).
  - Callback will be called upon a hash being found, with the callback_args being passed in as-is to the callback. Return a non-zero value from the callback to cause the overall function to shutdown the library.
  - The callback will block the library as it does not implement threading of any type.
  - This function is blocking, the only way to close the function is to close the socket externally.

If using the raw version of the library, the above functions are not implemented. The following functions are available in both versions of the library:

In `ntlmssp.h`:

```c
void *create_ntlmssp_handle(void);
void clean_ntlmssp_handle(void *handle, uint64_t seconds);
void free_ntlmssp_handle(void *handle);
int8_t handle_ntlmssp_raw(void *handle, uint8_t *buf, int32_t len, ntlmssp_callback_t callback, void *callback_args);
```

- create_ntlmssp_handle
  - This function will return a handle that is used to keep track of internal variables. Several handles can exist at the same time.
  - On error, 0 is returned
- clean_ntlmssp_handle
  - Given a valid handle, clean out anything older than the *seconds* parameter
- free_ntlmssp_handle
  - Free a handle and all of its internal allocations
- handle_ntlmssp_raw
  - This is the function that manages the logic behind extracting NetNTLM hashes from packets. Since this requires a new packet on every call, this function is *not* blocking.
  - Provide a raw ethernet packet in the buf parameter, of size len.
  - The callback works the same as the handle_ntlmssp function.

The following is the structure provided in the callback:

```c
struct netntlm_t
{
	// Timestamp when added to the stack
	// Used for cleaning up based on a timeout
	uint64_t timestamp;

	// Fields of the hash that are needed
	char *domain;
	char *username;
	char *challenge_str;
	char *proof_str;
	char *response_str;

	// Raw fields of the hash
	uint64_t challenge;
	uint8_t proof[16];
	uint8_t *response;
	uint64_t response_size;

	// Other useful data
	char src_ip[16];
	char dst_ip[16];
	uint16_t src_port;
	uint16_t dst_port;

	// The completed hash string
	char *complete_hash;
};
```

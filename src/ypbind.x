
const YPMAXDOMAIN = 256;
typedef string domainname<YPMAXDOMAIN>;
typedef char olddomainname;

#ifdef RPC_HDR
%/*
% * Response structure and overall result status codes.  Success and failure
% * represent two separate response message types.
% */
#endif

enum ypbind_resptype {
	YPBIND_SUCC_VAL = 1,
	YPBIND_FAIL_VAL = 2
};

struct ypbind_binding {
    opaque ypbind_binding_addr[4]; /* In network order */
    opaque ypbind_binding_port[2]; /* In network order */
};

union ypbind_resp switch (ypbind_resptype ypbind_status) {
case YPBIND_FAIL_VAL:
        unsigned ypbind_error;
case YPBIND_SUCC_VAL:
        ypbind_binding ypbind_bindinfo;
};

#ifdef RPC_HDR
%
%/* Detailed failure reason codes for response field ypbind_error*/
#endif

const YPBIND_ERR_ERR    = 1;	/* Internal error */
const YPBIND_ERR_NOSERV = 2;	/* No bound server for passed domain */
const YPBIND_ERR_RESC   = 3;	/* System resource allocation failure */

#ifdef RPC_HDR
%
%/*
% * Request data structure for ypbind "Set domain" procedure.
% */
#endif
struct ypbind_oldsetdom {
        char ypoldsetdom_domain[YPMAXDOMAIN];
        ypbind_binding ypoldsetdom_binding;
};

#ifdef RPC_HDR
%#define ypoldsetdom_addr ypoldsetdom_binding.ypbind_binding_addr
%#define ypoldsetdom_port ypoldsetdom_binding.ypbind_binding_port
#endif

struct ypbind_setdom {
	domainname ypsetdom_domain;
	ypbind_binding ypsetdom_binding;
	unsigned ypsetdom_vers;
};

#ifdef RPC_HDR
%
%/*
% * NIS binding protocol
% */
#endif
program YPBINDPROG {
	version YPBINDOLDVERS {
		void
		YPBINDPROC_OLDNULL(void) = 0;

		ypbind_resp
		YPBINDPROC_OLDDOMAIN(olddomainname) = 1;

		void
		YPBINDPROC_OLDSETDOM(ypbind_oldsetdom) = 2;
	} = 1;
	version YPBINDVERS {
		void
		YPBINDPROC_NULL(void) = 0;

		ypbind_resp
		YPBINDPROC_DOMAIN(domainname) = 1;

		void
		YPBINDPROC_SETDOM(ypbind_setdom) = 2;
	} = 2;
} = 100007;

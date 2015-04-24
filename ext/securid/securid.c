#include "ruby.h"
#include "acexport.h"
#include "securid.h"

// module RSA
static VALUE rb_mRSA;

// module RSA::SecurID
static VALUE rb_mRSASecurID;

// class RSA::SecurID::SecurIDError < StandardError
static VALUE rb_eSecurIDError;

// class RSA::SecurID::Session
static VALUE rb_cRSASecurIDSession;

// ID used for session storage on RSA::SecurID::Session
ID securid_id_session;

// ID used for status storage on RSA::SecurID::Session
ID securid_id_session_status;

// IDs used to identify RSA::SecurID::Session constants
ID securid_id_session_authenticated;
ID securid_id_session_denied;
ID securid_id_session_change_pin;
ID securid_id_session_resynchronize;

static void securid_session_free(void *ptr)
{
	securid_session_t *session = (securid_session_t *)ptr;
	if (session->handle != SDI_HANDLE_NONE)
	{
		SD_Close(session->handle);
		session->handle = SDI_HANDLE_NONE;
	}
}

static void securid_session_mark(void *ptr)
{
	
}

static size_t securid_session_size(void const *ptr)
{
	return sizeof(securid_session_t);
}

struct rb_data_type_struct securid_session_data_type = {
	"RSA::SecurID::Session Storage",
	{
		securid_session_mark, /* dmark */
		securid_session_free, /* dfree */
		securid_session_size, /* dsize */
		{NULL, NULL}
	},
	NULL,
	NULL,
	RUBY_TYPED_FREE_IMMEDIATELY
};

// def RSA::SecurID.authenticate(username, passcode)
static VALUE securid_authenticate(VALUE self, VALUE username, VALUE passcode)
{
	// the authentication handle representing a single authentication
	// context, i.e. a multi-step authentication attempt
	SDI_HANDLE aceHdl;

	// a string containing the username
	SD_CHAR *userID = StringValuePtr(username);

	// a string containing the passcode
	SD_CHAR *pass   = StringValuePtr(passcode);

	// a hint to the developer about how long to display the next
	// prompt string for the user
	SD_I32  respTimeout;

	// an indicator of the maximum number of bytes of data expected
	// in the next developer-supplied response
	SD_I32  nextRespLen;

	// a developer-supplied character array to be filled in by the
	// API with the string that the caller uses as the next message
	// displayed to the user
	SD_CHAR promptStr[512];

	// the size of the developer-supplied storage for the prompt
	// string
	SD_I32  promptStrLen;

	// a flag that is set by the API to indicate whether more data
	// is needed by the authentication context
	SD_BOOL moreData;

	// a flag that guides the developer as to whether the next
	// expected response is echoed to the screen
	SD_BOOL echoFlag;

	// the final authentication status
	SD_I32  authStatus;

	// initialize the authentication library. even though it will only do anything
	// the first time it is called, subsequent calls should still return true if the
	// initialization previously succeeded.
	if (!AceInitialize())
	{
		// the authentication library failed to initialize.
		rb_raise(rb_eSecurIDError, "Failed to initialize authentication library");
	}

	int retVal;

	// reset size of prompt string
	promptStrLen = sizeof(promptStr);

	// start our authentication attempt by first sending the username to
	// the authentication manager.
	retVal = AceStartAuth(&aceHdl, userID, strlen(userID), &moreData, &echoFlag, &respTimeout, &nextRespLen, promptStr, &promptStrLen);

	if (retVal != ACM_OK)
	{
		// the authentication attempt could not be started for some reason.
		rb_raise(rb_eSecurIDError, "Failed to start authentication attempt - Code %d", retVal);
	}

	if (!moreData)
	{
		// the authentication manager should have asked for a passcode
		AceCloseAuth(aceHdl);
		rb_raise(rb_eSecurIDError, "Authentication manager did not ask for a passcode");
	}

	// reset size of prompt string
	promptStrLen = sizeof(promptStr);

	// the authentication manager wants us to prompt the user for more data. because
	// this function is non-interactive, we assume the manager wants the passcode. since
	// we already have it, we'll pass it along without prompting the user.
	retVal = AceContinueAuth(aceHdl, pass, strlen(pass), &moreData, &echoFlag, &respTimeout, &nextRespLen, promptStr, &promptStrLen);

	if (retVal != ACM_OK)
	{
		// the authentication attempt could not be continued for some reason.
		AceCloseAuth(aceHdl);
		rb_raise(rb_eSecurIDError, "Failed to continue authentication attempt - Code %d", retVal);
	}

	if (moreData)
	{
		// either our assumption that the authentication manager wanted the passcode was
		// incorrect, or something else went wrong.
		AceCloseAuth(aceHdl);
		rb_raise(rb_eSecurIDError, "Authentication manager asked for more than a passcode");
	}

	// ask the authentication manager for the status of this authentication attempt.
	retVal = AceGetAuthenticationStatus(aceHdl, &authStatus);

	// finalize this authentication attempt by closing our handle.
	AceCloseAuth(aceHdl);

	if (retVal != ACE_SUCCESS)
	{
		// the authentication status could not be retrieved for some reason.
		rb_raise(rb_eSecurIDError, "Failed to retrieve authentication status - Code %d", retVal);
	}

	// check the status of the authentication attempt and return true or false.
	if (authStatus == ACM_OK)
		return Qtrue;
	else if (authStatus == ACM_ACCESS_DENIED)
		return Qfalse;

	rb_raise(rb_eSecurIDError, "Unexpected authentication status - Code %d", authStatus);
}

// Checks that the status of the session `self` matches the constant identified by `status_id`. Pass
// NULL for `status_id` to check if the the status of `self` is Qnil.
void securid_session_check_status(VALUE self, ID status_id) {
	VALUE current_status = rb_ivar_get(self, securid_id_session_status);
	VALUE compared_status;
	int invalid_state;

	if (status_id)
	{
		compared_status = rb_const_get(rb_cRSASecurIDSession, status_id);
		invalid_state = !rb_eql(current_status, compared_status);
	} else {
		invalid_state = !NIL_P(current_status);
	}

	if (invalid_state)
	{
		rb_raise(rb_eSecurIDError, "Session is in an invalid state for the requested operation");
	}
}

// def RSA::SecurID::Session.new
static VALUE securid_session_initalize(VALUE self)
{
	securid_session_t *session;
	VALUE session_data;

	// Allocate a new securid_session_t and wrap it as a ruby object
	session_data = TypedData_Make_Struct(rb_cData, securid_session_t, &securid_session_data_type, session);
	session->handle = SDI_HANDLE_NONE;

	// Stick our new securid_session_t into an instance variable on self 
	rb_ivar_set(self, securid_id_session, session_data);

	// Initalize our status to nil
	rb_ivar_set(self, securid_id_session_status, Qnil);

	return self;
}

// def RSA::SecurID::Session#authenticate(username, passcode) -> status
static VALUE securid_session_authenticate(VALUE self, VALUE username, VALUE passcode)
{
	int return_value;
	VALUE session_data;
	VALUE status = Qnil;
	securid_session_t *session;
	SD_CHAR *username_str;
	SD_CHAR *passcode_str;

	// Check that we are in an allowed state
	securid_session_check_status(self, NULL);

	// Fetch our securid_session_t from self
	session_data = rb_ivar_get(self, securid_id_session);
	TypedData_Get_Struct(session_data, securid_session_t, &securid_session_data_type, session);

	// Convert our arguments to C Strings
	username_str = StringValueCStr(username);
	passcode_str = StringValueCStr(passcode);

	// Initalize the session handler
	if (SD_Init(&session->handle) != ACM_OK)
	{
		rb_raise(rb_eSecurIDError, "Failed to initialize session handler");
	}

	// Lock the username, part of the Two Step Authentication flow
	if (SD_Lock(session->handle, username_str) != ACM_OK)
	{
		rb_raise(rb_eSecurIDError, "Failed to lock username");
	}

	return_value = SD_Check(session->handle, passcode_str, username_str);

	if (return_value == ACM_OK)
	{
		// We are authenticated
		status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_authenticated);
	} else if (return_value == ACM_ACCESS_DENIED) 
	{
		// We are denied
		status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_denied);
	} else if (return_value == ACM_NEXT_CODE_REQUIRED)
	{
		// We need the user to resynchronize the token
		status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_resynchronize);
	} else if (return_value == ACM_NEW_PIN_REQUIRED)
	{
		// We need the user to enter a new pin
		status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_change_pin);
	} else {
		// Internal error of some sort
		rb_raise(rb_eSecurIDError, "Failed to authenticate the user");
	}

	// Update our status
	rb_ivar_set(self, securid_id_session_status, status);

	return status;
}

// def RSA::SecurID::Session#change_pin(pin) -> BOOL
static VALUE securid_session_change_pin(VALUE self, VALUE pin)
{
	VALUE session_data;
	securid_session_t *session;
	SD_CHAR *pin_str;

	// Check that we are in an allowed state
	securid_session_check_status(self, securid_id_session_change_pin);

	// Fetch our securid_session_t from self
	session_data = rb_ivar_get(self, securid_id_session);
	TypedData_Get_Struct(session_data, securid_session_t, &securid_session_data_type, session);

	// Convert our arguments to C Strings
	pin_str = StringValueCStr(pin);

	if (SD_Pin(session->handle, pin_str) != ACM_NEW_PIN_ACCEPTED)
	{
		// Changing pin failed for internal reasons
		rb_raise(rb_eSecurIDError, "Failed to change the pin");
	}

	// Update our status to be unstarted.
	rb_ivar_set(self, securid_id_session_status, Qnil);

	return Qtrue;
}

// def RSA::SecurID::Session#cancel_pin -> BOOL
static VALUE securid_session_cancel_pin(VALUE self)
{
	VALUE session_data;
	securid_session_t *session;
	SD_CHAR *pin_str;

	// Check that we are in an allowed state
	securid_session_check_status(self, securid_id_session_change_pin);

	// Fetch our securid_session_t from self
	session_data = rb_ivar_get(self, securid_id_session);
	TypedData_Get_Struct(session_data, securid_session_t, &securid_session_data_type, session);

	if (SD_Pin(session->handle, NULL) != ACM_NEW_PIN_ACCEPTED)
	{
		rb_raise(rb_eSecurIDError, "Failed to cancel changing the pin");
	}

	// Update our status to be unstarted.
	rb_ivar_set(self, securid_id_session_status, Qnil);

	return Qtrue;
}

// def RSA::SecurID::Session#resychronize(passcode) -> status
static VALUE securid_session_resychronize(VALUE self, VALUE passcode)
{
	int return_value;
	VALUE session_data;
	VALUE status;
	securid_session_t *session;
	SD_CHAR *passcode_str;

	// Check that we are in an allowed state
	securid_session_check_status(self, securid_id_session_resynchronize);

	// Fetch our securid_session_t from self
	session_data = rb_ivar_get(self, securid_id_session);
	TypedData_Get_Struct(session_data, securid_session_t, &securid_session_data_type, session);

	// Convert our arguments to C Strings
	passcode_str = StringValueCStr(passcode);

	// Initalize the session handler
	return_value = SD_Next(session->handle, passcode_str);
	if (return_value == ACM_OK)
	{
		// We are authenticated
		status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_authenticated);
	} else if (return_value == ACM_ACCESS_DENIED)
	{
		// We are denied 
		status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_denied);
	} else {
		// Internal error of some sort
		rb_raise(rb_eSecurIDError, "Failed to synchronize the token");
	}

	// Update our status
	rb_ivar_set(self, securid_id_session_status, status);

	return status;
}

void Init_securid()
{
	securid_id_session = rb_intern("session_handler"); // hidden from the ruby runtime due to its name
	securid_id_session_status = rb_intern("@status");
	securid_id_session_authenticated = rb_intern("AUTHENTICATED");
	securid_id_session_denied = rb_intern("DENIED");
	securid_id_session_change_pin = rb_intern("MUST_CHANGE_PIN");
	securid_id_session_resynchronize = rb_intern("MUST_RESYNCHRONIZE");

	// module RSA
	rb_mRSA = rb_define_module("RSA");

	// module RSA::SecurID
	rb_mRSASecurID = rb_define_module_under(rb_mRSA, "SecurID");

	// class RSA::SecurID::SecurIDError < StandardError
	rb_eSecurIDError = rb_define_class_under(rb_mRSASecurID, "SecurIDError", rb_eStandardError);

	// def RSA::SecurID.authenticate(username, passcode)
	rb_define_module_function(rb_mRSASecurID, "authenticate", securid_authenticate, 2);

	// class RSA::SecurID::Session
	rb_cRSASecurIDSession = rb_define_class_under(rb_mRSASecurID, "Session", rb_cObject);

	// def RSA::SecurID::Session.new
	rb_define_private_method(rb_cRSASecurIDSession, "initialize", securid_session_initalize, 0);

	// def RSA::SecurID::Session#authenticate(username, passcode)
	rb_define_method(rb_cRSASecurIDSession, "authenticate", securid_session_authenticate, 2);

	// def RSA::SecurID::Session#change_pin(pin)
	rb_define_method(rb_cRSASecurIDSession, "change_pin", securid_session_change_pin, 1);

	// def RSA::SecurID::Session#cancel_pin
	rb_define_method(rb_cRSASecurIDSession, "cancel_pin", securid_session_cancel_pin, 0);

	// def RSA::SecurID::Session#resychronize
	rb_define_method(rb_cRSASecurIDSession, "resychronize", securid_session_resychronize, 1);
}

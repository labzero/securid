#include "ruby.h"
#include "acexport.h"
#include "status_display.h"
#include "securid.h"

#ifdef WIN32
  #include <winsock.h>
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

#define CTEST(v) ((v) ? Qtrue : Qfalse)

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

// ID used for test mode storage on RSA::SecurID::Session
ID securid_id_session_test_mode;

// symbol version of 'test_mode'
static VALUE rb_symTestMode;

// symbol version of 'resynchronize'
static VALUE rb_symResynchronize;

// symbol version of 'change_pin'
static VALUE rb_symChangePin;

// symbol version of 'denied'
static VALUE rb_symDenied;

// IDs used to identify RSA::SecurID::Session constants
ID securid_id_session_authenticated;
ID securid_id_session_denied;
ID securid_id_session_change_pin;
ID securid_id_session_resynchronize;

// symbols used to in the agent status hash
static VALUE rb_symConfigVersion; // 'config_version'
static VALUE rb_symMaxServers; // 'max_servers'
static VALUE rb_symMaxReplicas; // 'max_replicas'
static VALUE rb_symMaxRetries; // 'max_retries'
static VALUE rb_symBaseTimeout; // 'base_timeout'
static VALUE rb_symUseDES; // 'use_des'
static VALUE rb_symTrusted; // 'trusted'
static VALUE rb_symPort; // 'port'
static VALUE rb_symServiceName; // 'service_name'
static VALUE rb_symServiceProtocol; // 'service_protocol'
static VALUE rb_symServiceProtocolVersion; // 'service_protocol_version'
static VALUE rb_symServerReleaseNumber; // 'server_release_number'
static VALUE rb_symServers; // 'servers'
static VALUE rb_symMajor; // 'major'
static VALUE rb_symMinor; // 'minor'
static VALUE rb_symPatch; // 'patch'
static VALUE rb_symBuild; // 'build'
static VALUE rb_symAddress; // 'address'
static VALUE rb_symActiveAddress; // 'active_address'
static VALUE rb_symAliases; // 'aliases'
static VALUE rb_symDisplayStatus; // 'display_status'
static VALUE rb_symHostname; // 'hostname'
static VALUE rb_symPrimary; // 'primary'
static VALUE rb_symMaster; // 'master'
static VALUE rb_symSlave; // 'slave'
static VALUE rb_symSelectable; // 'selectable'
static VALUE rb_symEmergency; // 'emergency'
static VALUE rb_symSuspended; // 'suspended'
static VALUE rb_symAddressVerified; // 'address_verified'

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
// 0 for `status_id` to check if the the status of `self` is Qnil.
void securid_session_check_status(VALUE self, ID status_id)
{
  VALUE current_status = rb_ivar_get(self, securid_id_session_status);
  VALUE compared_status;
  int invalid_state;

  if (status_id)
  {
    compared_status = rb_const_get(rb_cRSASecurIDSession, status_id);
    invalid_state = !rb_eql(current_status, compared_status);
  } else
  {
    invalid_state = !NIL_P(current_status);
  }

  if (invalid_state)
  {
    rb_raise(rb_eSecurIDError, "Session is in an invalid state for the requested operation");
  }
}

int securid_session_is_test_mode(VALUE self)
{
  VALUE test_mode = rb_ivar_get(self, securid_id_session_test_mode);
  return RTEST(test_mode);
}

int securid_session_is_test_mode_resynchronize(VALUE self)
{
  VALUE test_mode = rb_ivar_get(self, securid_id_session_test_mode);
  return rb_eql(test_mode, rb_symResynchronize);
}

int securid_session_is_test_mode_change_pin(VALUE self)
{
  VALUE test_mode = rb_ivar_get(self, securid_id_session_test_mode);
  return rb_eql(test_mode, rb_symChangePin);
}

int securid_session_is_test_mode_denied(VALUE self)
{
  VALUE test_mode = rb_ivar_get(self, securid_id_session_test_mode);
  return rb_eql(test_mode, rb_symDenied);
}

// def RSA::SecurID::Session.new(options)
// options supports:
//    * test_mode: boolean reflecting if we are in test mode or not
//                 if value is :resynchronize the test mode will require token resynchronization
//                 if value is :change_pin the test mode will require a pin change
static VALUE securid_session_initalize(int argc, VALUE *argv, VALUE self)
{
  securid_session_t *session;
  VALUE session_data;
  VALUE options = Qnil;
  VALUE test_mode = Qfalse;

  rb_scan_args(argc, argv, "0:", &options);

  // Allocate a new securid_session_t and wrap it as a ruby object
  session_data = TypedData_Make_Struct(rb_cData, securid_session_t, &securid_session_data_type, session);
  session->handle = SDI_HANDLE_NONE;

  // Stick our new securid_session_t into an instance variable on self 
  rb_ivar_set(self, securid_id_session, session_data);

  // Initalize our status to nil
  rb_ivar_set(self, securid_id_session_status, Qnil);

  // Initalize our test_mode to the supplied option
  if (!NIL_P(options))
  {
    test_mode = rb_hash_aref(options, rb_symTestMode);
  }
  rb_ivar_set(self, securid_id_session_test_mode, test_mode);

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
  securid_session_check_status(self, (ID)0);

  if (!securid_session_is_test_mode(self))
  {
    // Fetch our securid_session_t from self
    session_data = rb_ivar_get(self, securid_id_session);
    TypedData_Get_Struct(session_data, securid_session_t, &securid_session_data_type, session);

    // Convert our arguments to C Strings
    username_str = StringValueCStr(username);
    passcode_str = StringValueCStr(passcode);

    // Initalize the session handler
    return_value = SD_Init(&session->handle);
    if (return_value != ACM_OK)
    {
      rb_raise(rb_eSecurIDError, "Failed to initialize session handler - code %d", return_value);
    }

    // Lock the username, part of the Two Step Authentication flow
    return_value = SD_Lock(session->handle, username_str);
    if (return_value != ACM_OK)
    {
      rb_raise(rb_eSecurIDError, "Failed to lock username - code %d", return_value);
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
    } else
    {
      // Internal error of some sort
      rb_raise(rb_eSecurIDError, "Failed to authenticate the user - code %d", return_value);
    }
  } else
  {
    if (securid_session_is_test_mode_resynchronize(self))
    {
      // Force resynchronize in resynchronization test mode
      status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_resynchronize);
    } else if (securid_session_is_test_mode_change_pin(self))
    {
      // Force pin change in pin change test mode
      status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_change_pin);
    } else if (securid_session_is_test_mode_denied(self))
    {
      // Force denied in denied test mode
      status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_denied);
    } else
    {
      // Force success in test mode
      status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_authenticated);
    }
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
  int return_value;

  // Check that we are in an allowed state
  securid_session_check_status(self, securid_id_session_change_pin);

  if (!securid_session_is_test_mode(self))
  {
    // Fetch our securid_session_t from self
    session_data = rb_ivar_get(self, securid_id_session);
    TypedData_Get_Struct(session_data, securid_session_t, &securid_session_data_type, session);

    // Convert our arguments to C Strings
    pin_str = StringValueCStr(pin);

    return_value = SD_Pin(session->handle, pin_str);
    if (return_value != ACM_NEW_PIN_ACCEPTED)
    {
      // Changing pin failed for internal reasons
      rb_raise(rb_eSecurIDError, "Failed to change the pin - code %d", return_value);
    }
  } else
  {
    if (securid_session_is_test_mode_change_pin(self))
    {
      // exit pin change test mode for regular test mode
      rb_ivar_set(self, securid_id_session_test_mode, Qtrue);
    }
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
  int return_value;

  // Check that we are in an allowed state
  securid_session_check_status(self, securid_id_session_change_pin);

  if (!securid_session_is_test_mode(self))
  {
    // Fetch our securid_session_t from self
    session_data = rb_ivar_get(self, securid_id_session);
    TypedData_Get_Struct(session_data, securid_session_t, &securid_session_data_type, session);

    return_value = SD_Pin(session->handle, NULL);
    if (return_value != ACM_NEW_PIN_ACCEPTED)
    {
      rb_raise(rb_eSecurIDError, "Failed to cancel changing the pin - code %d", return_value);
    }
  }

  // Update our status to be unstarted.
  rb_ivar_set(self, securid_id_session_status, Qnil);

  return Qtrue;
}

// def RSA::SecurID::Session#resynchronize(passcode) -> status
static VALUE securid_session_resynchronize(VALUE self, VALUE passcode)
{
  int return_value;
  VALUE session_data;
  VALUE status;
  securid_session_t *session;
  SD_CHAR *passcode_str;

  // Check that we are in an allowed state
  securid_session_check_status(self, securid_id_session_resynchronize);

  if (!securid_session_is_test_mode(self))
  {
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
      rb_raise(rb_eSecurIDError, "Failed to synchronize the token - code %d", return_value);
    }
  } else {
    if (securid_session_is_test_mode_resynchronize(self))
    {
      // exit resynchronization test mode for regular test mode
      rb_ivar_set(self, securid_id_session_test_mode, Qtrue);
    }
    // Force success in test mode
    status = rb_const_get(rb_cRSASecurIDSession, securid_id_session_authenticated);
  }

  // Update our status
  rb_ivar_set(self, securid_id_session_status, status);

  return status;
}

static VALUE securid_agent_status(VALUE self) {
  VALUE status = Qfalse;
  VALUE server_release_number;
  VALUE server_details;
  VALUE servers;
  VALUE server_aliases;
  VALUE display_status;
  S_status_display agent_status;
  DISP_SRVR_INFO * server_info;
  int return_value, i, j, str_length;
  struct in_addr addr;

  // Initialize the library. Safe to call multiple times.
  if (AceInitialize() != SD_TRUE) {
    rb_raise(rb_eSecurIDError, "Failed to initialize authentication library");
  }

  // Make sure we are zero'd
  memset(&agent_status, 0, sizeof(agent_status));
  // Set the struct size so the SDK can identify the version used
  agent_status.u32Size = (SD_U32) sizeof(agent_status);
  // Fetch the agent status
  return_value = AceAgentStatusDisplay(&agent_status);

  if (return_value == ACE_SUCCESS) {
    status = rb_hash_new();

    // Populate status hash
    rb_hash_aset(status, rb_symConfigVersion, INT2NUM(agent_status.config_version));
    rb_hash_aset(status, rb_symMaxServers, INT2NUM(agent_status.acmmaxservers));
    rb_hash_aset(status, rb_symMaxReplicas, INT2NUM(agent_status.acmmaxreplicas));
    rb_hash_aset(status, rb_symMaxRetries, INT2NUM(agent_status.acmmaxretries));
    rb_hash_aset(status, rb_symBaseTimeout, INT2NUM(agent_status.acmbasetimeout));
    rb_hash_aset(status, rb_symUseDES, INT2NUM(agent_status.use_des));
    rb_hash_aset(status, rb_symTrusted, INT2NUM(agent_status.trusted));
    rb_hash_aset(status, rb_symPort, INT2NUM(agent_status.acmport));
    rb_hash_aset(status, rb_symServiceProtocolVersion, INT2NUM(agent_status.server_hi_protocol));

    str_length = strnlen(agent_status.acmservice, sizeof(agent_status.acmservice) / sizeof(SD_CHAR));
    rb_hash_aset(status, rb_symServiceName, rb_str_new(agent_status.acmservice, str_length));

    str_length = strnlen(agent_status.acmprotocol, sizeof(agent_status.acmprotocol) / sizeof(SD_CHAR));
    rb_hash_aset(status, rb_symServiceProtocol, rb_str_new(agent_status.acmprotocol, str_length));

    // Populate release number hash
    server_release_number = rb_hash_new();
    rb_hash_aset(server_release_number, rb_symMajor, INT2NUM(agent_status.server_release_from_server[0]));
    rb_hash_aset(server_release_number, rb_symMinor, INT2NUM(agent_status.server_release_from_server[1]));
    rb_hash_aset(server_release_number, rb_symPatch, INT2NUM(agent_status.server_release_from_server[2]));
    rb_hash_aset(server_release_number, rb_symBuild, INT2NUM(agent_status.server_release_from_server[3]));
    rb_hash_aset(status, rb_symServerReleaseNumber, server_release_number);

    servers = rb_ary_new();

    // Populate server array
    for (i = 0; i < agent_status.acmmaxreplicas; ++i) {
      server_info = &agent_status.acm_servers[i];

      if (!(server_info->addr && server_info->hostname)) {
        continue;
      }

      server_details = rb_hash_new();

      str_length = strnlen(server_info->hostname, DISP_LENHOSTNAME);
      rb_hash_aset(server_details, rb_symHostname, str_length ? rb_str_new(server_info->hostname, str_length) : Qnil);

      addr.s_addr = server_info->addr;
      rb_hash_aset(server_details, rb_symAddress, server_info->addr ? rb_str_new2(inet_ntoa(addr)) : Qnil);

      addr.s_addr = server_info->active_addr;
      rb_hash_aset(server_details, rb_symActiveAddress, server_info->active_addr ? rb_str_new2(inet_ntoa(addr)) : Qnil);

      // build server aliases array
      server_aliases = rb_ary_new();
      for (j = 0; j < DISP_MAXALIASES; ++j) {
        if (!server_info->aliases[j]) {
          continue;
        }
        addr.s_addr = server_info->aliases[j];
        rb_ary_push(server_aliases, rb_str_new2(inet_ntoa(addr)));
      }
      rb_hash_aset(server_details, rb_symAliases, server_aliases);

      display_status = rb_hash_new();
      rb_hash_aset(display_status, rb_symPrimary, CTEST(server_info->display_status & DISP_STATUS_PRIMARY));
      rb_hash_aset(display_status, rb_symMaster, CTEST(server_info->display_status & DISP_MSTR_SLAVE && i == 0));
      rb_hash_aset(display_status, rb_symSlave, CTEST(server_info->display_status & DISP_MSTR_SLAVE && i > 0));
      rb_hash_aset(display_status, rb_symSelectable, CTEST(server_info->display_status & DISP_STATUS_SELECTABLE));
      rb_hash_aset(display_status, rb_symEmergency, CTEST(server_info->display_status & DISP_STATUS_EMERGENCY));
      rb_hash_aset(display_status, rb_symSuspended, CTEST(server_info->display_status & DISP_STATUS_SUSPENDED));
      rb_hash_aset(server_details, rb_symDisplayStatus, display_status);

      // Add server details to servers array
      rb_ary_push(servers, server_details);
    }

    // Add servers array to status hash
    rb_hash_aset(status, rb_symServers, servers);
  }

  return status;
}

void Init_securid()
{
  securid_id_session = rb_intern("session_handler"); // hidden from the ruby runtime due to its name
  securid_id_session_status = rb_intern("@status");
  securid_id_session_test_mode = rb_intern("@test_mode");
  securid_id_session_authenticated = rb_intern("AUTHENTICATED");
  securid_id_session_denied = rb_intern("DENIED");
  securid_id_session_change_pin = rb_intern("MUST_CHANGE_PIN");
  securid_id_session_resynchronize = rb_intern("MUST_RESYNCHRONIZE");
  rb_symTestMode = ID2SYM(rb_intern("test_mode"));
  rb_symResynchronize = ID2SYM(rb_intern("resynchronize"));
  rb_symChangePin = ID2SYM(rb_intern("change_pin"));
  rb_symDenied = ID2SYM(rb_intern("denied"));

  rb_symConfigVersion = ID2SYM(rb_intern("config_version"));
  rb_symMaxServers = ID2SYM(rb_intern("max_servers"));
  rb_symMaxReplicas = ID2SYM(rb_intern("max_replicas"));
  rb_symMaxRetries = ID2SYM(rb_intern("max_retries"));
  rb_symBaseTimeout = ID2SYM(rb_intern("base_timeout"));
  rb_symUseDES = ID2SYM(rb_intern("use_des"));
  rb_symTrusted = ID2SYM(rb_intern("trusted"));
  rb_symPort = ID2SYM(rb_intern("port"));
  rb_symServiceName = ID2SYM(rb_intern("service_name"));
  rb_symServiceProtocol = ID2SYM(rb_intern("service_protocol"));
  rb_symServiceProtocolVersion = ID2SYM(rb_intern("service_protocol_version"));
  rb_symServerReleaseNumber = ID2SYM(rb_intern("server_release_number"));
  rb_symServers = ID2SYM(rb_intern("servers"));
  rb_symMajor = ID2SYM(rb_intern("major"));
  rb_symMinor = ID2SYM(rb_intern("minor"));
  rb_symPatch = ID2SYM(rb_intern("patch"));
  rb_symBuild = ID2SYM(rb_intern("build"));
  rb_symAddress = ID2SYM(rb_intern("address"));
  rb_symActiveAddress = ID2SYM(rb_intern("active_address"));
  rb_symAliases = ID2SYM(rb_intern("aliases"));
  rb_symDisplayStatus = ID2SYM(rb_intern("display_status"));
  rb_symHostname = ID2SYM(rb_intern("hostname"));
  rb_symPrimary = ID2SYM(rb_intern("primary"));
  rb_symMaster = ID2SYM(rb_intern("master"));
  rb_symSlave = ID2SYM(rb_intern("slave"));
  rb_symSelectable = ID2SYM(rb_intern("selectable"));
  rb_symEmergency = ID2SYM(rb_intern("emergency"));
  rb_symSuspended = ID2SYM(rb_intern("suspended"));
  rb_symAddressVerified = ID2SYM(rb_intern("address_verified"));

  // module RSA
  rb_mRSA = rb_define_module("RSA");

  // module RSA::SecurID
  rb_mRSASecurID = rb_define_module_under(rb_mRSA, "SecurID");

  // class RSA::SecurID::SecurIDError < StandardError
  rb_eSecurIDError = rb_define_class_under(rb_mRSASecurID, "SecurIDError", rb_eStandardError);

  // def RSA::SecurID.authenticate(username, passcode)
  rb_define_module_function(rb_mRSASecurID, "authenticate", securid_authenticate, 2);

  // def RSA::SecurID.agent_status
  rb_define_module_function(rb_mRSASecurID, "agent_status", securid_agent_status, 0);

  // class RSA::SecurID::Session
  rb_cRSASecurIDSession = rb_define_class_under(rb_mRSASecurID, "Session", rb_cObject);

  // def RSA::SecurID::Session.new
  rb_define_private_method(rb_cRSASecurIDSession, "initialize", securid_session_initalize, -1);

  // def RSA::SecurID::Session#authenticate(username, passcode)
  rb_define_method(rb_cRSASecurIDSession, "authenticate", securid_session_authenticate, 2);

  // def RSA::SecurID::Session#change_pin(pin)
  rb_define_method(rb_cRSASecurIDSession, "change_pin", securid_session_change_pin, 1);

  // def RSA::SecurID::Session#cancel_pin
  rb_define_method(rb_cRSASecurIDSession, "cancel_pin", securid_session_cancel_pin, 0);

  // def RSA::SecurID::Session#resynchronize
  rb_define_method(rb_cRSASecurIDSession, "resynchronize", securid_session_resynchronize, 1);
}

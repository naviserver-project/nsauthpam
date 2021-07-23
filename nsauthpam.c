/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://mozilla.org/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License (the "GPL"), in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under either the License or the GPL.
 */

/*
 * nsauthpam.c --
 *
 */

#include "ns.h"
#include <security/pam_appl.h>

struct pam_cred {
  char *username;
  char *password;
};

NS_EXPORT int Ns_ModuleVersion = 1;
NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;

/*
 * Static functions defined in this file.
 */

static Tcl_ObjCmdProc AuthObjCmd;
static Ns_TclTraceProc AddCmds;


/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *      Module entry point.  The server runs this function each time
 *      the module is loaded.  The configurable greeting is checked and
 *      a function to create the Tcl command for each interp is
 *      registered.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *      Global numLoaded counter is incremented.
 *
 *----------------------------------------------------------------------
 */

Ns_ReturnCode
Ns_ModuleInit(const char *server, const char *module)
{
    Ns_TclRegisterTrace(server, AddCmds, 0, NS_TCL_TRACE_CREATE);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * AddCmds --
 *
 *      Register module commands for a freshly created Tcl interp.
 *
 * Results:
 *      NS_OK or NS_ERROR.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static Ns_ReturnCode
AddCmds(Tcl_Interp *interp, const void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_authpam", AuthObjCmd, (ClientData)arg, NULL);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * pam_conv --
 *
 * PAM conversation function
 * Accepts: number of messages
 *	    vector of messages
 *	    pointer to response return
 *	    application data
 *
 * Results:
 *      PAM_SUCCESS if OK, response vector filled in, else PAM_CONV_ERR
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
pam_conv(int msgs, const struct pam_message **msg, struct pam_response **resp, void *appdata)
{
    int i;
    struct pam_cred *cred = (struct pam_cred *) appdata;
    struct pam_response *reply = malloc(sizeof (struct pam_response) * msgs);

    for (i = 0; i < msgs; i++) {
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_ON:	/* assume want user name */
            reply[i].resp_retcode = PAM_SUCCESS;
            reply[i].resp = strdup(cred->username);
            break;

        case PAM_PROMPT_ECHO_OFF:	/* assume want password */
            reply[i].resp_retcode = PAM_SUCCESS;
            reply[i].resp = strdup(cred->password);
            break;

        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            reply[i].resp_retcode = PAM_SUCCESS;
            reply[i].resp = NULL;
            break;

        default:			/* unknown message style */
            free(reply);
            return PAM_CONV_ERR;
        }
    }
    *resp = reply;
    return PAM_SUCCESS;
}

/*
 *----------------------------------------------------------------------
 *
 * AuthObjCmd --
 *
 *   Verifies username and pasword with specified PAM service
 *
 * Results:
 *      TCL_ERROR if error occurred, otherwise TCL_OK.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
AuthObjCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int rc, cmd;

    enum commands {
        cmdAuth
    };

    static const char *sCmd[] = {
        "auth",
        0
    };

    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "command ?args?");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp,objv[1],sCmd,"command",TCL_EXACT,(int *)&cmd) != TCL_OK) {
        return TCL_ERROR;
    }

    switch(cmd) {
     case cmdAuth: {
        pam_handle_t *hdl;
        struct pam_conv conv;
        struct pam_cred cred;
        int delay = 0;
        char *user = NULL, *password = NULL, *service = NULL;
        char *rhost = NULL, *authtok = NULL, *tty = NULL;

        Ns_ObjvSpec opts[] = {
            {"-tty",     Ns_ObjvString, &tty,       NULL},
            {"-rhost",   Ns_ObjvString, &rhost,     NULL},
            {"-authtok", Ns_ObjvString, &authtok,   NULL},
            {"-delay",   Ns_ObjvInt,    &delay, NULL},
            {"--",       Ns_ObjvBreak,  NULL,       NULL},
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec args[] = {
            {"service",   Ns_ObjvString, &service,  NULL},
            {"username",  Ns_ObjvString, &user,     NULL},
            {"password",  Ns_ObjvString, &password, NULL},
            {NULL, NULL, NULL, NULL}
        };

        if (Ns_ParseObjv(opts, args, interp, 2, objc, objv) != NS_OK) {
          return TCL_ERROR;
        }

        conv.conv = &pam_conv;
        conv.appdata_ptr = &cred;
        cred.username = user;
        cred.password = password;

        rc = pam_start(service, user, &conv, &hdl);

#if !defined(__APPLE__)
	/* is not available in Mac OS X 10.7.4 although post seem to
	   indicate that is is in 10.6 ore newer */
        if (delay > 0) {
            pam_fail_delay(hdl, delay);
        }
#endif

        if (rc == PAM_SUCCESS) {
            if (rhost != NULL) {
                pam_set_item(hdl, PAM_RHOST, rhost);
            }
            if (authtok != NULL) {
                pam_set_item(hdl, PAM_AUTHTOK, authtok);
            }
            if (tty != NULL) {
                pam_set_item(hdl, PAM_TTY, tty);
            }
            rc = pam_authenticate(hdl, 0);
        }
        if (rc == PAM_SUCCESS) {
            pam_acct_mgmt(hdl, 0);
        }
        pam_end(hdl, rc);

        Tcl_SetObjResult(interp, Tcl_NewIntObj(rc == PAM_SUCCESS ? 1 : 0));
        break;
     }
    }
    return TCL_OK;
}


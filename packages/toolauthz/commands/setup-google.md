---
description: Walk through Google OAuth setup to get a refresh token for TAP
---

Help the user get a Google OAuth refresh token and add it as a credential in the TAP dashboard. TAP already has a shared OAuth client — the user only needs a refresh token.

Follow these steps exactly:

1. Tell the user to open the Google OAuth Playground:
   https://developers.google.com/oauthplayground/

2. Tell them to click the **gear icon** (top right) and check **"Use your own OAuth credentials"**, then enter the Client ID and Client Secret shown in the TAP dashboard (visible when adding a Google credential).

3. Ask what Google APIs they need. Help them select the right scopes in the left panel:
   - Gmail: `https://mail.google.com/`
   - Calendar: `https://www.googleapis.com/auth/calendar`
   - Drive: `https://www.googleapis.com/auth/drive`
   - Sheets: `https://www.googleapis.com/auth/spreadsheets`

4. Tell them to click **"Authorize APIs"**, sign in with their Google account, and grant access.

5. Tell them to click **"Exchange authorization code for tokens"** and copy the **Refresh Token** from the response.

6. Tell them to go to the TAP dashboard → Credentials → **+ Add Credential** → select **Google Workspace** → paste the refresh token → click **Create**.

That's it. TAP handles token refresh automatically using the shared OAuth client.

$ARGUMENTS

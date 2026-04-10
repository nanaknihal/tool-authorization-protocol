---
description: Walk through Telegram credential setup for TAP
---

Help the user set up a Telegram personal account credential so their agent can interact with Telegram through TAP. This is for the agent to act as the user on Telegram — the approval bot is already running on the platform.

Follow these steps exactly:

1. Tell the user to go to https://my.telegram.org/apps and log in with their phone number.

2. Tell them to create a new application (or use an existing one) and note the **API ID** (a number) and **API Hash** (a hex string).

3. Tell them to run this command in their terminal to generate a session string (requires Python 3.8+):

   ```bash
   pip install telethon -q && python3 -c "
   from telethon.sync import TelegramClient; from telethon.sessions import StringSession
   c = TelegramClient(StringSession(), int(input('API ID: ')), input('API Hash: '))
   c.start(); print('\nSession string:\n' + c.session.save())
   "
   ```

   It will prompt for their API ID, API Hash, phone number, and a verification code from Telegram. They should copy the session string it prints at the end.

4. Warn them: **keep this session string safe** — anyone with it can access their Telegram account.

5. Tell them to go to the TAP dashboard → Credentials → **+ Add Credential** → select **Telegram** → enter the API ID, API Hash, and Session String → click **Create**.

6. Tell them that after setup, agents should call the Telegram credential through TAP using the Telethon bridge endpoints like `/me`, `/dialogs`, `/messages`, `/send`, and `/reply`. They should **not** use Telegram Bot API methods like `getMe`, `getUpdates`, or `sendMessage`, and they should not target `https://api.telegram.org/...`.

$ARGUMENTS

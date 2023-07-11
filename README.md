# AzuKI - Azure Key Impersonator

## Usage

1. Download your public certificate from Azure:

    ![Azure Download PFX](https://github.com/namazso/AzuKI/assets/8676443/f92069dd-b12f-47af-ae53-f2e6831eaae4)

    Note that this will contain your private key too unless you imported or generated it as unexportable. In this case, import into your store and export only the public key.

2. Configure your environment variables as described in the next section.

3. Use signtool with the received file and the `/dlib` argument of signtool, like this:

    `signtool sign /f pub.pfx /dlib AzuKI.dll ...other params`

## Configuration

Configuration is done with environment variables. Either of

- `AZUKI_TOKEN`
- `AZUKI_TENANT_ID`, `AZUKI_CLIENT_ID`, `AZUKI_CLIENT_SECRET`

must be defined.

### Variables

`AZUKI_VAULT_DOMAIN`

Example: `contoso.vault.azure.net`

`AZUKI_KEY_NAME`

Example `my_code_key`

`AZUKI_TOKEN` (optional)

Example: `eyJ0eXAiOiJKV1QiLCJhbG...MjhKWAWU9A`

`AZUKI_TENANT_ID` (optional)

Example: `7dc9753f-51f1-427c-b792-226b652798b3`

`AZUKI_CLIENT_ID` (optional)

Example: `8584a481-6fd6-442d-8d80-99cd02cc2d79`

`AZUKI_CLIENT_SECRET` (optional)

Example: `5sfHBvk4^7AQHAeMngG3ro$%kF*6wF$B$Don@36U`

`AZUKI_LOGIN_HOST` (optional)

Default: `login.microsoftonline.com`

`AZUKI_RESOURCE` (optional)

Default: `https://vault.azure.net`

## License

    MIT License
    
    Copyright (c) namazso 2023
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

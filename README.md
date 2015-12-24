# arkc-server-udptransmit
ArkC is a lightweight proxy based on Python and Twisted, and uses PyCrypto for encryption. It is designed to be proof to IP blocking measures.

ArkC-Server-udptransmit is the dnsserver-side utility, it checks whether the data is legal and transfers the decrypted data to main server.

##Requirement

Running ArkC-Server-udptransmit requires Python 2.7 and Crypto
##Run

python main.py [-c <Path of the config Json file, default = config.json>]

In this version, any private certificate should be in the form of PEM without encryption, while any public certificate should be in the form of ssh-rsa. Note that ssh-rsa files should not include extra blank lines because they are used for hash.

For the configuration file, you can find an example here:

{ 

    "remote_host": "x.x.x.x",
    "remote_port": "x",
    "clients": [
        ["/home/tony/arkc/testfiles/client1.pub", <sha1 of client1's private key>],
        ["/home/tony/arkc/testfiles/client2.pub", <sha1 of client2's private key>]
    ]
  }

For a full list of settings:


| Index name            |                Value Type & Description               | Required / Default   |
| ----------------------|:------------------------------------------------------| --------------------:|
| servers               | list, (address, port, path of pub) pairs              | REQUIRED             |
| clients               | list, (path of client pub, sha1 of client pri) pairs  | REQUIRED             |

##Acknowledgements

The client-end software adapted part of the pyotp library created by Mark Percival <m@mdp.im>. His code is reused under Python Port copyright, license attached.

##License

Copyright 2015 ArkC contributers

The ArkC-client and ArkC-server utilities are licensed under GNU GPLv2. You should obtain a copy of th e license with the software.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

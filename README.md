<h1 align="center">
Bells Core [BEL]
</h1>

<div align="center">

[![BellsBadge](https://img.shields.io/badge/Bells-Coin-blue)](https://bellscoin.com)
[![MuchWow](https://img.shields.io/badge/OG-Coin-yellow.svg)](https://bellscoin.com)

</div>

## This branch contains Bells Core 3.1.1rc2 (release candidate 2).

## What is Bells?
Bells is a joke cryptocurrency referencing the "Bells" currency in Animal Crossing. Created by Billy Markus in 2013 right before Dogecoin and revived in 2023, it's Dogecoin's older brother. The shared "Nintondo" mention - a playful nod to Nintendo - in both genesis blocks underscores their sibling connection. 

[Visit blockchain explorer](https://nintondo.io/bells/mainnet/explorer)

## Development and contributions
Developers work in their own trees, then submit pull requests when they think their feature or bug fix is ready.

## Usage 💻
To start your journey with Bells Core, see the [installation guide](INSTALL.md).

The JSON-RPC API provided by Bells Core is self-documenting and can be browsed with `bells-cli help`, while detailed information for each command can be viewed with `bells-cli help <command>`. Alternatively, see the [Bitcoin Core documentation](https://developer.bitcoin.org/reference/rpc/) - which implements a similar protocol - to get a browsable version.

## Frequently Asked Questions

### How many Bells can exist?
Infinite.

But supply is effectively capped by the low block reward. Currently, with the block subsidy at only 2 BEL per block and a circulating supply of approximately 61M BEL, about 1M BEL are produced per year. At this rate, it would take around 430 years to reach a supply of 500M BEL.

### Ports
| Function | mainnet | testnet | regtest |
| :------- |--------:| ------: | ------: |
| P2P      |   19919 |   29919 |   18444 |
| RPC      |    8332 |   18332 |   18443 |

## License ⚖️
Bells Core is released under the terms of the MIT license. See
[COPYING](COPYING) for more information or see
[opensource.org](https://opensource.org/licenses/MIT)

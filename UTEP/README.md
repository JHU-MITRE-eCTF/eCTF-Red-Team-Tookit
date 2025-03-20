# UTEP
## Pirated Subscription
UTEP design does not check decoder ID for subscription update.

## Pesky Neighbor
UTEP design bypasses timestamp check for Emergency channel 0. Thus attacker can simply replay channel 0 frame, making it in violation of security requirement 3 (monotonically increasing timestamps).

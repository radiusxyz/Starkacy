# scripts/transfer_funds.py
from nile.common import ETH_TOKEN_ADDRESS
from nile.utils import to_uint, hex_address

async def run(nre):
  accounts = await nre.get_accounts(predeployed=True)
  account = accounts[0]

  # define the recipient address
  # recipient = "0x057792c44b1e9e349ee549ed018f7225f927bd2b01b6277a1cb94da5fb9421ed"
  # recipient = "0x7e1f4f5f197363b05c791e9e502a31f2484f382cfde1c38f1ad5d793754bea9"
  recipient = "0x057792c44b1e9e349ee549ed018f7225f927bd2b01b6277a1cb94da5fb9421ed"
  # define the amount to transfer
  amount = 2 * 10 ** 18

  print(
    f"Transferring {amount} WEI\n"
    f"from {hex_address(account.address)}\n"
    f"to   {recipient}\n"
  )

  # If we don't pass a max_fee, nile will estimate the transaction fee by default
  tx = await account.send(ETH_TOKEN_ADDRESS, "transfer", [recipient, *to_uint(amount)])

  tx_status, *_ = await tx.execute(watch_mode="track")

  print(tx_status.status, tx_status.error_message or "")
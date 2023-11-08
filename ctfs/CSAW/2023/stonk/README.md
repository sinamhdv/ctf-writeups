In this challenge we can buy, sell, and trade stocks for money. When we request a
trade of X for Y, the price of X will immediately be subtracted from our balance in
`postTrade` function.
Then there is a thread which will pop trade requests from a queue and add the minimum of price of
X and Y to our balance (i.e. either accept or reject the trade request) in `market_scrape` function. This thread has
a race condition with the previous thread. When we send more than 10 requests to the server in a 10-second period,
the server will restore our account's state to its previous value using the `bkup` dictionary in `threadTransact` function.
This happens after the price of X is subtracted from our balance in a trade request. If this account restore event
happens before the `market_scrape` thread gives us money equal to the price of one of X or Y, and if price of X is less than Y, we will
get our money back twice. This way we can increase our money until we can buy the flag.

# Tau5 Discovery

This is a UDP-multicast-based discovery system for finding similar peers on the local network.

It is similar in intent - but much smaller in scope to mDNS in that it's specifically designed for discovering other Tau5 nodes and sharing a snippet of text (likely to be used as JSON for node info).

The design is heavily based on Ableton Link and in fact was mostly implemented by LLMs (Claude and ChatGPT) using the code from Ableton Link's Discovery system as training data (https://github.com/Ableton/link).

This puts this code in unusual copyright terrain. There's definitely a valid argument to suggest that this is a derivative work of Ableton Link as it's mostly implemented by LLMs and those LLMs used copyright code as part of the process of implementing this system. Therefore, to maintain a decent ethical position, this project is GPL licensed to match Ableton Link.

Also, as this code has largely been written by an LLM - it should be treated as being unsafe until further testing and code reading. If you're happy reading C++ - please do take a good look at the code base and please do suggest any improvements. This is a starting position only and I intend for the codebase to improve over time.

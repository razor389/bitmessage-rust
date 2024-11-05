RustBitmessasge
===============

This is an implementation of https://github.com/Bitmessage/PyBitmessage with some modifications for improved security and efficiency, incorporating some of the suggestions made here: https://zolagonano.github.io/blog/posts/a-very-technical-look-at-bitmessage

We want to implement the prefix filtering proposal to improve scalability: https://wiki.bitmessage.org/index.php/Scalability_through_Prefix_Filtering


TODO:
-message compression
-broadcast new address to nodes w/ keys
-getkey request from addresses
-making nodes run at ip/port
-timestamping messages
-ttl for messasges
-message ack
-communication between nodes
-ability to blacklist nodes
-appropriate citations/licensing/readme
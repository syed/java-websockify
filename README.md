# Introduction
This is a simple webosckets proxy written in Java. It converts frontend websckets to backend pure TCP connections. Primary motivation for this implementation was to make NoVNC run with a Java backend.

# Building and running

Maven is used to build the project. You can build it by

```
git clone http://github.com:syed/java-websockify.git
cd java-websockify
mvn compile
mvn install
```

This will build the jar in the `target/` directory. Run it by

```
java -jar target/target/java-websockify-1.0-SNAPSHOT
```

# TODO

* Make it take command line args
* Make it multi-threaded

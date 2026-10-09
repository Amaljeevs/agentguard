# Repeatable performance measurements

Build the library with `mvn install` first, then:

```shell
mvn -f benchmarks/pom.xml package
java -jar benchmarks/target/benchmarks.jar -prof gc -rf json -rff benchmarks/target/results.json
```

JMH measures policy evaluation with 10/100/1000 nonmatching deny rules and a
wildcard grant, plus nested map sanitization. Defaults use two forks, three
warmups, and five measurements. Return values are consumed by JMH to prevent
dead-code elimination. The policy and request are prepared outside measurement.

For a quick wiring check (not a performance claim):

```shell
java -jar benchmarks/target/benchmarks.jar -p ruleCount=10 -f 1 -wi 1 -i 2 -w 500ms -r 500ms
```

Report CPU, OS, JDK, commit, workload, and full JSON results when comparing
versions. These measurements exclude Spring proxies, networking, databases,
approval storage, and logging I/O; they are not end-to-end latency guarantees.

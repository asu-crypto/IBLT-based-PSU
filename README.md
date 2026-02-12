# IBLT-PSU

#### Building the Docker container

To build the container with all our project's build requirements execute the following command while in the root of our project repository directory.

```bash
sudo docker build -t iblt-based-psu:latest .
```

Alternatively, you can execute the bash script `build-img.sh`. Just be sure to execute the script while in the root of our project repository directory.

### Running the docker container

The user can execute the built container by executing the following container.

```bash
sudo docker run -it --rm --privileged --cap-add=NET_ADMIN iblt-based-psu:latest bash
```

Alternatively, you can execute the bash script `run-it.sh`. Just be sure to execute the script while in the root of our project repository directory.


### Building our benchmarks 

To build our benchmarks while inside the Docker container execute the bash script `build-bench.sh`. As a result, a folder `build` will be created containing the `psu_bench` executable.

### Running our benchmarks

All our benchmarks were implemented as part of the same file `src/benchmarks/psu.bench.cpp` using the [Catch2](https://github.com/catchorg/Catch2) libary. As a result, any of the benchmarks used to produce the measurements presented in our paper can be run by executing `build\psu_bench` with the correct arguments. For example, if the user desires to execute the benchmark for optimized for the LAN setting with input set sizes $n=2^{14}$ they should execute `build\psu_bench` in the following way:

```
./psu_bench --benchmark-samples 10 "[full][n=2^14][lan]"
```

The `--benchmark-samples 10` argument tells [Catch2](https://github.com/catchorg/Catch2) to execute the bechmark $10$ times and produce measurements based on these $10$ executions. Below we have a sample of the output produced when the previous command is executed.

```
Filters: [full] [n=2^14] [lan]
Randomness seeded to: 1217556386

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
psu_bench is a Catch2 v3.7.1 host application.
Run with -? for options

-------------------------------------------------------------------------------
setup and online phase for n=2^14 set sizes using asio sockets
-------------------------------------------------------------------------------
/home/ubuntu/src/benchmarks/psu.bench.cpp:637
...............................................................................

benchmark name                       samples       iterations    est run time
                                     mean          low mean      high mean
                                     std dev       low std dev   high std dev
-------------------------------------------------------------------------------
n=2^14                                          10             1     531.43 us 
                                        76.8972 ms    76.4658 ms    77.3266 ms 
                                        696.151 us    503.775 us    997.378 us 
                                                                               

===============================================================================
All tests passed (66 assertions in 1 test case)
```

To execute the benchmark optimized for the WAN setting with input set sizes $n=2^{18}$ a user should execute `build\psu_bench` in the following way:

```
./psu_bench --benchmark-samples 10 "[full][n=2^18][wan]"
```

Here, again, the benchmark would be executed 10 times. Please note that a user may provide an arbitrary $n$ value when executing `psu_benchmake`. A user can only choose a value $n$ from the set $\{2^{14},2^{16},2^{18},2^{20},2^{22}\}$. This is because we only implemented benchmarks for this values of $n$.

![Important](https://img.shields.io/badge/Important-Red?style=for-the-badge&color=red)

It is important to understand that when running a benchmark for a specific network setting (LAN or WAN), the benchmark is only instantiating the protocol with parameters that are optimized for the specific network setting. The benchmark doesn't automatically configure the container such to simulate the specified network setting. The user is expected to configure the container to simulate the setting as they wish. If the user does not configure the container, the benchmark will be executed over a local socket incuring virtually no communication related costs during the execution. 

We included the bash script `sn.sh` as part of the `src` folder that can be used to configure the container such that it simulates latency and a bandwidth limit during the protocol execution. This script must be executed before a benchmark is executed. Here is an example of how to execute the bash script:

```
bash sn.sh on 80 200
```

This specific command call configures the container such that it simulates a 80ms latency and a 200 Megabits bandwidth. Meanwhile, the following call simulates a 0.1ms latency and 10Gbit bandwidth.

```
bash sn.sh on 0.1 10000
```

Please remember to execute the following command between calls to `bash sn.sh on`.

```
bash sn.sh off
```

Additionally, the use may execute the following command to check the current configuration.


```
bash sn.sh status
```

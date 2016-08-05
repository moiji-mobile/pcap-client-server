package main

import (
    "fmt";
    "strings";
    zmq "github.com/pebbe/zmq4"
)

func main() {
    subscriber, _ := zmq.NewSocket(zmq.SUB)
    defer subscriber.Close()
    subscriber.Connect("tcp://localhost:6666")

    subscriber.SetSubscribe("")

    for {
        msg, _ := subscriber.RecvMessage(0)
        if (strings.HasPrefix(msg[0], "event.v1")) {
            fmt.Println("Got event message.. %d", len(msg), msg)
        } else if (strings.HasPrefix(msg[0], "data.v1")) {
            fmt.Println("Got data message.. %d", len(msg), msg)
        }
    }

}

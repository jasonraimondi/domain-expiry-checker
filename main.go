package main

import (
    "fmt"
    "time"

    "github.com/jasonraimondi/domain-expiry-check/whois"
)

func main() {
    res, err := whois.QueryHost("jasonraimondi.com")
    if err != nil {
        fmt.Println(err)
        return
    }
    time_string := res.Output["Registry Expiry Date"][0]
    t, _ := time.Parse(time.RFC3339, time_string)
    now := time.Now()

    duration, _ := time.ParseDuration("168h")

    fmt.Println(t, duration)
    t = t.Add(duration)
    fmt.Println(t)
    if now.Unix() > t.Unix() {
        fmt.Println("yes, the domain is almost expiring")
    } else {
        fmt.Println("no, we have a while to go")
    }
}

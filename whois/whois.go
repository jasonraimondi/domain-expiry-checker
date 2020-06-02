package whois

//
// This was sourced from https://raw.githubusercontent.com/xellio/whois/master/whois.go
// https://github.com/xellio/whois/blob/master/LICENSE
//

import (
    "encoding/json"
    "errors"
    "net"
    "net/url"
    "os/exec"
    "regexp"
    "strings"
    "time"
)

//
// Result struct
//
type Result struct {
    IP         net.IP
    Host       string
    Raw        []byte
    Output     map[string][]string
    GatherTime time.Duration
}

//
// Query whois data for given url
//
func Query(urlToQuery string, args ...string) (r *Result, err error) {
    u, err := url.Parse(urlToQuery)
    if err != nil {
        return nil, err
    }
    return QueryHost(u.Host, args...)
}

//
// QueryHost queries whois data for given host
//
func QueryHost(host string, args ...string) (r *Result, err error) {
    r = &Result{
        Host: host,
    }
    arguments := append([]string{host}, args...)
    if err = r.execute(arguments); err != nil {
        hp := strings.Split(host, ".")
        if len(hp) > 2 {
            return QueryHost(strings.Join(hp[1:], "."), args...)
        }
    }

    return
}

//
// QueryIP queries whois data for given net.IP
//
func QueryIP(ip net.IP, args ...string) (r *Result, err error) {
    r = &Result{
        IP: ip,
    }
    args = append([]string{ip.String()}, args...)
    err = r.execute(args)
    return
}

//
// Execute the whois command using the given args
//
func (r *Result) execute(args []string) error {

    path, err := exec.LookPath("whois")
    if err != nil {
        return err
    }

    start := time.Now()
    out, err := exec.Command(path, args...).Output()
    if err != nil {
        if err.Error() != "exit status 2" {
            return err
        }
    }

    r.GatherTime = time.Since(start)
    r.Raw = out
    r.Output = make(map[string][]string)

    _, err = isValidResponse(out)
    if err != nil {
        return err
    }

    singleLines := strings.Split(string(out), "\n")

    re := regexp.MustCompile("^[#%>]+")
    for _, line := range singleLines {
        if re.MatchString(line) {
            continue
        }
        lineParts := strings.Split(line, ": ")
        if len(lineParts) == 2 {
            tk := strings.TrimSpace(lineParts[0])
            r.Output[tk] = append(r.Output[tk], strings.TrimSpace(lineParts[1]))
        }
    }

    return nil
}

//
// Sometimes a failing whois looks like a working one
// In some cases we can find a trigger in the result (like status)
// Example:
//    URL: 1.f.ix.de/scale/geometry/246/q75/imgs/18/2/3/3/7/1/5/6/Volkswagen-Werk-in-Brasilien-1953-118a4f16e7756311.jpeg
// 	  Host: 1.f.ix.de
//    Result:
//    ```
//	  Domain: 1.f.ix.de
//    Status: invalid
//
//    ```
// Triggers we use right now:
// 		- a valid whois response should have a minimum of 5 lines
//		I will add more triggers as they appear or become nescessary (like checking the status field if present)
//
func isValidResponse(response []byte) (valid bool, err error) {

    singleLines := strings.Split(string(response), "\n")
    if len(singleLines) < 5 {
        err = errors.New("invalid response detected. We assume that a valid whois response has at minimum 5 lines")
        return
    }
    valid = true
    return
}

//
// JSON returns r,Output parsed as JSON
//
func (r *Result) JSON() (data []byte, err error) {
    data, err = json.Marshal(r.Output)
    return
}

//
// String return r.Outout as string (json)
//
func (r *Result) String() string {
    data, err := r.JSON()
    if err != nil {
        return ""
    }
    return string(data)
}

package hibp

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	packageVersion = "0.5.0"
	backendURL     = "https://api.pwnedpasswords.com"
	userAgent      = "pwned-passwords-golang/" + packageVersion
)

// Client holds a connection to the HIBP API.
type Client struct {
	client     *http.Client
	UserAgent  string
	BackendURL *url.URL
}

// NewClient creates a new Client with the appropriate connection details and services used for
// communicating with the API.
func NewClient() *Client {
	baseURL, _ := url.Parse(backendURL)

	return &Client{
		client:     http.DefaultClient,
		BackendURL: baseURL,
		UserAgent:  userAgent,
	}
}

// SetHTTPClient sets a *http.Client for the HIBP Client to use. Useful for customising timeout behaviour etc.
func (c *Client) SetHTTPClient(client *http.Client) *Client {
	c.client = client
	return c
}

// NewRequest creates an API request. A relative URL can be provided in urlPath, which will be resolved
// to the BackendURL of the Client.
func (c *Client) NewRequest(method, urlPath string, body interface{}) (*http.Request, error) {
	rel, err := url.Parse(urlPath)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)

	if body != nil {
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, c.BackendURL.ResolveReference(rel).String(), buf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", c.UserAgent)

	return req, nil
}

// Do sends an API request and returns the API response.
func (c *Client) Do(req *http.Request) ([]string, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr := resp.Body.Close(); err == nil {
			err = rerr
		}
	}()

	// Error if anything else but 200.
	// The API should always return a 200 (unless something is wrong) as per
	// https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected API response status: %v", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Response is returned as new-line'd string, split and return.
	return strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n"), err
}

// Compromised will build and execute a request to HIBP to check to see if the passed value is compromised or not.
func (c *Client) Compromised(value string) (bool, error) {
	if value == "" {
		return false, errors.New("value for compromised check cannot be empty")
	}

	hashedStr := hashString(value)
	prefix := strings.ToUpper(hashedStr[:5])
	suffix := strings.ToUpper(hashedStr[5:])

	request, err := c.NewRequest("GET", fmt.Sprintf("range/%s", prefix), nil)
	if err != nil {
		return false, err
	}

	response, err := c.Do(request)
	if err != nil {
		return false, err
	}

	for _, target := range response {
		if len(target) >= 37 && target[:35] == suffix {
			if _, err = strconv.ParseInt(target[36:], 10, 64); err != nil {
				return false, err
			}

			return true, err
		}
	}

	return false, err
}

// hashString will return a sha1 hash of the given value.
func hashString(value string) string {
	alg := sha1.New()
	alg.Write([]byte(value))

	return strings.ToUpper(hex.EncodeToString(alg.Sum(nil)))
}

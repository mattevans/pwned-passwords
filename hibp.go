package hibp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	packageVersion = "0.0.1"
	backendURL     = "https://api.pwnedpasswords.com"
	userAgent      = "pwned-passwords-golang/" + packageVersion
)

// Client holds a connection to the HIBP API.
type Client struct {
	client     *http.Client
	AppID      string
	UserAgent  string
	BackendURL *url.URL

	// Services used for communicating with the API.
	Pwned *PwnedService
	Cache *CacheService
}

type service struct {
	client *Client
}

// NewClient creates a new Client with the appropriate connection details and
// services used for communicating with the API.
func NewClient() *Client {
	// Init new http.Client.
	httpClient := http.DefaultClient

	// Parse BE URL.
	baseURL, _ := url.Parse(backendURL)

	c := &Client{
		client:     httpClient,
		BackendURL: baseURL,
		UserAgent:  userAgent,
	}

	c.Pwned = &PwnedService{client: c}
	c.Cache = &CacheService{client: c}
	return c
}

// NewRequest creates an API request. A relative URL can be provided in urlPath,
// which will be resolved to the BackendURL of the Client.
func (c *Client) NewRequest(method, urlPath string, body interface{}) (*http.Request, error) {
	// Parse our URL.
	rel, err := url.Parse(urlPath)
	if err != nil {
		return nil, err
	}

	// Resolve to absolute URI.
	u := c.BackendURL.ResolveReference(rel)

	buf := new(bytes.Buffer)
	if body != nil {
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	// Create the request.
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	// Add our packages UA.
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
		return nil, fmt.Errorf("Unexpected API response status: %v", resp.StatusCode)
	}

	// Parse our resp.Body.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Response is returned as new-line'd string, split and return.
	return strings.Split(string(body), "\r\n"), err
}

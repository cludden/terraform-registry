package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cludden/terraform-registry/mocks"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandlerFindProviderPackage(t *testing.T) {
	var dynamo mocks.DynamoDBAPI
	os.Setenv("AWS_ACCESS_KEY_ID", "foo")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "bar")
	s3 := s3.New(session.Must(session.NewSession()), aws.NewConfig().WithRegion("us-east-1"))

	s := Service{
		bucket: aws.String("terraform-registry"),
		prefix: "providers/v1",
		table:  aws.String("terraform-registry"),

		dynamo:   &dynamo,
		s3:       s3,
		validate: validator.New(),
	}

	handler := mux.NewRouter()
	s.Register(handler)

	cases := []struct {
		desc   string
		req    func() (*http.Request, error)
		assert func(*http.Response)
	}{
		{
			desc: "not found",
			req: func() (*http.Request, error) {
				return http.NewRequest("GET", "https://localhost:8000/foo", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			},
		},
		{
			desc: "dynamo error",
			req: func() (*http.Request, error) {
				dynamo.On("GetItemWithContext", mock.Anything, mock.Anything).Once().Return(nil, awserr.New(dynamodb.ErrCodeTableNotFoundException, "", errors.New("")))
				return http.NewRequest("GET", "https://localhost:8000/foo/bar/1.2.3/download/linux/amd64", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				dynamo.AssertCalled(t, "GetItemWithContext", mock.Anything, mock.Anything)
			},
		},
		{
			desc: "no version",
			req: func() (*http.Request, error) {
				dynamo.On("GetItemWithContext", mock.Anything, mock.Anything).Once().Return(nil, nil)
				return http.NewRequest("GET", "https://localhost:8000/foo/bar/1.2.3/download/linux/amd64", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
				dynamo.AssertCalled(t, "GetItemWithContext", mock.Anything, mock.Anything)
			},
		},
		{
			desc: "no package",
			req: func() (*http.Request, error) {
				version := Version{
					Platforms: []Platform{
						{
							Arch: "amd64",
							OS:   "linux",
						},
					},
					Protocols: []string{"5.0"},
					Version:   "1.2.3",
				}
				item, err := dynamodbattribute.MarshalMap(version)
				if !assert.NoError(t, err) {
					return nil, err
				}

				dynamo.On("GetItemWithContext", mock.Anything, mock.Anything).Once().Return(&dynamodb.GetItemOutput{
					Item: item,
				}, nil)
				return http.NewRequest("GET", "https://localhost:8000/foo/bar/1.2.3/download/darwin/amd64", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
				dynamo.AssertCalled(t, "GetItemWithContext", mock.Anything, mock.Anything)
			},
		},
		{
			desc: "no key",
			req: func() (*http.Request, error) {
				version := Version{
					GPGPublicKeyID: "abcdefg",
					Platforms: []Platform{
						{
							Arch: "amd64",
							OS:   "linux",
						},
					},
					Protocols: []string{"5.0"},
					Version:   "1.2.3",
				}
				item, err := dynamodbattribute.MarshalMap(version)
				if !assert.NoError(t, err) {
					return nil, err
				}

				dynamo.On("GetItemWithContext", mock.Anything, mock.MatchedBy(func(input *dynamodb.GetItemInput) bool {
					return *input.Key["pk"].S != gpgPublicKeyPK
				})).Once().Return(&dynamodb.GetItemOutput{
					Item: item,
				}, nil)

				dynamo.On("GetItemWithContext", mock.Anything, mock.MatchedBy(func(input *dynamodb.GetItemInput) bool {
					return *input.Key["pk"].S == gpgPublicKeyPK
				})).Once().Return(nil, nil)

				return http.NewRequest("GET", "https://localhost:8000/foo/bar/1.2.3/download/linux/amd64", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				dynamo.AssertNumberOfCalls(t, "GetItemWithContext", 2)
			},
		},
		{
			desc: "success",
			req: func() (*http.Request, error) {
				key := GPGPublicKey{
					ASCIIArmor: "123456",
					KeyID:      "abcdefg",
				}
				keyItem, err := dynamodbattribute.MarshalMap(key)
				if !assert.NoError(t, err) {
					return nil, err
				}

				version := Version{
					Platforms: []Platform{
						{
							Arch: "amd64",
							OS:   "linux",
						},
					},
					Protocols: []string{"5.0"},
					Version:   "1.2.3",
				}
				item, err := dynamodbattribute.MarshalMap(version)
				if !assert.NoError(t, err) {
					return nil, err
				}

				dynamo.On("GetItemWithContext", mock.Anything, mock.MatchedBy(func(input *dynamodb.GetItemInput) bool {
					return *input.Key["pk"].S != gpgPublicKeyPK
				})).Once().Return(&dynamodb.GetItemOutput{
					Item: item,
				}, nil)

				dynamo.On("GetItemWithContext", mock.Anything, mock.MatchedBy(func(input *dynamodb.GetItemInput) bool {
					return *input.Key["pk"].S == gpgPublicKeyPK
				})).Once().Return(&dynamodb.GetItemOutput{
					Item: keyItem,
				}, nil)

				return http.NewRequest("GET", "https://localhost:8000/foo/bar/1.2.3/download/linux/amd64", nil)
			},
			assert: func(resp *http.Response) {
				if !assert.Equal(t, http.StatusOK, resp.StatusCode) {
					body, _ := ioutil.ReadAll(resp.Body)
					t.Log(string(body))
				}
				dynamo.AssertNumberOfCalls(t, "GetItemWithContext", 2)
				dynamo.AssertCalled(t, "GetItemWithContext", mock.Anything, mock.MatchedBy(func(input *dynamodb.GetItemInput) bool {
					assert.NotNil(t, input)
					assert.Equal(t, *s.table, *input.TableName)
					assert.Equal(t, versionPK(Provider{"foo", "bar"}), *input.Key["pk"].S)
					return true
				}))
				body, err := ioutil.ReadAll(resp.Body)
				assert.NoError(t, err)
				var out FindProviderPackageOutput
				assert.NoError(t, json.Unmarshal(body, &out))
				assert.Equal(t, "linux", out.OS)
				assert.Equal(t, "amd64", out.Arch)
				assert.Equal(t, "terraform-provider-bar_v1.2.3_linux_amd64.zip", out.Filename)
				assert.NotEmpty(t, out.DownloadURL)
				assert.Contains(t, out.SHASumsURL, "checksums.txt")
				assert.Contains(t, out.SHASumsSignatureURL, "checksums.txt.sig")
				assert.Contains(t, out.Protocols, "5.0")
				assert.Len(t, out.SigningKeys.GPGPublicKeys, 1)
				assert.Equal(t, "abcdefg", out.SigningKeys.GPGPublicKeys[0].KeyID)
				assert.Equal(t, "123456", "123456")
			},
		},
	}

	for _, c := range cases {
		// reset dynamo mock
		dynamo = mocks.DynamoDBAPI{}
		s.dynamo = &dynamo

		req, err := c.req()
		if !assert.NoError(t, err) {
			continue
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		c.assert(w.Result())
	}
}

func TestHandlerListAvailableVersions(t *testing.T) {
	dynamo := &mocks.DynamoDBAPI{}
	s3 := &mocks.S3API{}

	s := Service{
		bucket: aws.String("terraform-registry"),
		prefix: "providers/v1",
		table:  aws.String("terraform-registry"),

		dynamo:   dynamo,
		s3:       s3,
		validate: validator.New(),
	}

	handler := mux.NewRouter()
	s.Register(handler)

	cases := []struct {
		desc   string
		req    func() (*http.Request, error)
		assert func(*http.Response)
	}{
		{
			desc: "not found",
			req: func() (*http.Request, error) {
				return http.NewRequest("GET", "https://localhost:8000/foo", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			},
		},
		{
			desc: "dynamo error",
			req: func() (*http.Request, error) {
				dynamo.On("QueryPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Once().Return(awserr.New(dynamodb.ErrCodeTableNotFoundException, "", errors.New("")))
				return http.NewRequest("GET", "https://localhost:8000/foo/bar/versions", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				dynamo.AssertCalled(t, "QueryPagesWithContext", mock.Anything, mock.Anything, mock.Anything)
			},
		},
		{
			desc: "no versions",
			req: func() (*http.Request, error) {
				dynamo.On("QueryPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Once().Return(nil)
				return http.NewRequest("GET", "https://localhost:8000/foo/bar/versions", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				dynamo.AssertCalled(t, "QueryPagesWithContext", mock.Anything, mock.Anything, mock.Anything)
				body, err := ioutil.ReadAll(resp.Body)
				assert.NoError(t, err)
				var out ListAvailableVersionsOutput
				assert.NoError(t, json.Unmarshal(body, &out))
				assert.Len(t, out.Versions, 0)
			},
		},
		{
			desc: "success",
			req: func() (*http.Request, error) {
				dynamo.On("QueryPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Once().Run(func(args mock.Arguments) {
					fn, ok := args.Get(2).(func(*dynamodb.QueryOutput, bool) bool)
					if !ok {
						return
					}

					version := Version{
						Platforms: []Platform{
							{
								Arch: "amd64",
								OS:   "linux",
							},
						},
						Protocols: []string{"5.0"},
						Version:   "1.2.3",
					}

					item, err := dynamodbattribute.MarshalMap(version)
					if !assert.NoError(t, err) {
						return
					}

					fn(&dynamodb.QueryOutput{
						Items: []map[string]*dynamodb.AttributeValue{item},
					}, true)
				}).Return(nil)
				return http.NewRequest("GET", "https://localhost:8000/foo/bar/versions", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				dynamo.AssertCalled(t, "QueryPagesWithContext", mock.Anything, mock.Anything, mock.Anything)
				body, err := ioutil.ReadAll(resp.Body)
				assert.NoError(t, err)
				var out ListAvailableVersionsOutput
				assert.NoError(t, json.Unmarshal(body, &out))
				assert.Len(t, out.Versions, 1)
				assert.Equal(t, "1.2.3", out.Versions[0].Version)
				assert.Contains(t, out.Versions[0].Protocols, "5.0")
				assert.Contains(t, out.Versions[0].Platforms, Platform{
					Arch: "amd64",
					OS:   "linux",
				})
			},
		},
	}

	for _, c := range cases {
		req, err := c.req()
		if !assert.NoError(t, err) {
			continue
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		c.assert(w.Result())
	}
}

func TestHandlerPublishVersion(t *testing.T) {
	dynamo := &mocks.DynamoDBAPI{}
	s3 := &mocks.S3API{}

	s := Service{
		bucket: aws.String("terraform-registry"),
		prefix: "providers/v1",
		table:  aws.String("terraform-registry"),

		dynamo:   dynamo,
		s3:       s3,
		validate: validator.New(),
	}

	handler := mux.NewRouter()
	s.Register(handler)

	cases := []struct {
		desc   string
		req    func() (*http.Request, error)
		assert func(*http.Response)
	}{
		{
			desc: "not found",
			req: func() (*http.Request, error) {
				return http.NewRequest("PUT", "https://localhost:8000/foo", nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			},
		},
		{
			desc: "bad payload",
			req: func() (*http.Request, error) {
				return http.NewRequest("PUT", "https://localhost:8000/foo/bar/1.2.3", bytes.NewBuffer([]byte(`{"foo":"bar"}`)))
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
		},
		{
			desc: "dynamo error",
			req: func() (*http.Request, error) {
				dynamo.On("PutItemWithContext", mock.Anything, mock.AnythingOfType("*dynamodb.PutItemInput")).Once().Return(nil, awserr.New(dynamodb.ErrCodeTableNotFoundException, "", errors.New("")))
				return http.NewRequest("PUT", "https://localhost:8000/foo/bar/1.2.3", bytes.NewBuffer([]byte(`{"platforms":[{"os":"linux","arch":"amd64"}],"protocols":["5.0"]}`)))
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				dynamo.AssertCalled(t, "PutItemWithContext", mock.Anything, mock.AnythingOfType("*dynamodb.PutItemInput"))
			},
		},
		{
			desc: "success",
			req: func() (*http.Request, error) {
				dynamo.On("PutItemWithContext", mock.Anything, mock.AnythingOfType("*dynamodb.PutItemInput")).Once().Return(&dynamodb.PutItemOutput{}, nil)
				return http.NewRequest("PUT", "https://localhost:8000/foo/bar/1.2.3", bytes.NewBuffer([]byte(`{"platforms":[{"os":"linux","arch":"amd64"}],"protocols":["5.0"]}`)))
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				dynamo.AssertCalled(t, "PutItemWithContext", mock.Anything, mock.MatchedBy(func(input *dynamodb.PutItemInput) bool {
					assert.NotNil(t, input)
					assert.Equal(t, *s.table, *input.TableName)
					var version Version
					if err := dynamodbattribute.UnmarshalMap(input.Item, &version); err != nil {
						return false
					}
					assert.Equal(t, versionPK(Provider{"foo", "bar"}), version.PK)
					assert.Equal(t, "1.2.3", version.Version)
					assert.Contains(t, version.Protocols, "5.0")
					assert.Contains(t, version.Platforms, Platform{
						Arch: "amd64",
						OS:   "linux",
					})
					return true
				}))
			},
		},
	}

	for _, c := range cases {
		req, err := c.req()
		if !assert.NoError(t, err) {
			continue
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		c.assert(w.Result())
	}
}

func TestHandlerRegisterGPGPublicKey(t *testing.T) {
	var dynamo mocks.DynamoDBAPI
	s3 := &mocks.S3API{}

	s := Service{
		bucket:   aws.String("terraform-registry"),
		prefix:   "providers/v1",
		table:    aws.String("terraform-registry"),
		s3:       s3,
		validate: validator.New(),
	}

	keyFixture, err := ioutil.ReadFile("testdata/key.json")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var k GPGPublicKey
	if !assert.NoError(t, json.Unmarshal(keyFixture, &k)) {
		t.FailNow()
	}

	handler := mux.NewRouter()
	s.Register(handler)

	cases := []struct {
		desc   string
		req    func() (*http.Request, error)
		assert func(*http.Response)
	}{
		{
			desc: "missing payload",
			req: func() (*http.Request, error) {
				return http.NewRequest("PUT", fmt.Sprintf("https://localhost:8000/gpg-public-keys/%s", k.KeyID), nil)
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
		},
		{
			desc: "bad payload",
			req: func() (*http.Request, error) {
				return http.NewRequest("PUT", fmt.Sprintf("https://localhost:8000/gpg-public-keys/%s", k.KeyID), bytes.NewBuffer([]byte(`{"foo":"bar"}`)))
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
		},
		{
			desc: "dynamo error",
			req: func() (*http.Request, error) {
				dynamo.On("PutItemWithContext", mock.Anything, mock.AnythingOfType("*dynamodb.PutItemInput")).Once().Return(nil, awserr.New(dynamodb.ErrCodeTableNotFoundException, "", errors.New("")))
				return http.NewRequest("PUT", fmt.Sprintf("https://localhost:8000/gpg-public-keys/%s", k.KeyID), bytes.NewBuffer(keyFixture))
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				dynamo.AssertCalled(t, "PutItemWithContext", mock.Anything, mock.AnythingOfType("*dynamodb.PutItemInput"))
			},
		},
		{
			desc: "success",
			req: func() (*http.Request, error) {
				dynamo.On("PutItemWithContext", mock.Anything, mock.AnythingOfType("*dynamodb.PutItemInput")).Once().Return(&dynamodb.PutItemOutput{}, nil)
				return http.NewRequest("PUT", fmt.Sprintf("https://localhost:8000/gpg-public-keys/%s", k.KeyID), bytes.NewBuffer(keyFixture))
			},
			assert: func(resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				dynamo.AssertCalled(t, "PutItemWithContext", mock.Anything, mock.MatchedBy(func(input *dynamodb.PutItemInput) bool {
					assert.NotNil(t, input)
					assert.Equal(t, *s.table, *input.TableName)
					var key GPGPublicKey
					if err := dynamodbattribute.UnmarshalMap(input.Item, &key); err != nil {
						return false
					}
					assert.Equal(t, gpgPublicKeyPK, key.PK)
					assert.Equal(t, k.KeyID, key.KeyID)
					assert.Equal(t, k.ASCIIArmor, key.ASCIIArmor)
					return true
				}))
			},
		},
	}

	for _, c := range cases {
		dynamo = mocks.DynamoDBAPI{}
		s.dynamo = &dynamo

		req, err := c.req()
		if !assert.NoError(t, err) {
			continue
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		c.assert(w.Result())
	}
}

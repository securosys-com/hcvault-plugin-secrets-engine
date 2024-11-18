/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.
*/

package testHelpers

// Map with all required parameters needed to access TSB
var ConfigParams map[string]interface{} = map[string]interface{}{
	"restapi":            "https://integration-test.cloudshsm.com",
	"auth":               "CERT",
	"certpath":           "../testHelpers/tsb-integration-test-client.crt",
	"keypath":            "../testHelpers/tsb-integration-test-client.key",
	"applicationKeyPair": "{\"privateKey\":\"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDK2cG1SMP0OaJC9zVEUYZGu9d1mrz9WVm2wXd/oUm/5K6AO0Y/324bm2pWegaRME7oFZvwPc3LSY9NQyjX6G2FT7PZZ1r/86Ak4p7veTHsmXnM+7Fv68U7S9Za4qpMXEtigqKSwBb7+XjIEiJtZVT3wclsxL/XCye6Y72DuxokmkpJh+yABzIYukos//Bh8Kh12Q3IOxerJlu/HJF6TknSO7xR1DtlPBFOuxo7JZKvJrbAAZ0GmjT5WkpE7GBcc4+ODM0HFPxAHgbt5eZp7+huWF+CoZCC0d/2TaVPf/LvvcTp1DKjxclYuugEF24S5HIpKfK3UKB+nik29j5sVjBFAgMBAAECggEAJ+zSHn8y6kfJswp69nZhSlzAXIpXNjo22Syc+4bgQB+fZOfFvN6aCl79gAXGcx8h+LYAGjnf3modBWT5jf1WSQ3V5S1dkND/rSLZi2K8O8g9W+YSF2g9Sp1zlDHWuO7Ve48gtmeOXovMhPxkwElYfucqYPkclRPB/wKQk3PpAljtv2JfI0a0BqA3uOZFNzonb5SROf6gaBJU3omW0j/jo1/ZMOXMkvtokrUhc4PIBBeKhZBxSr9NlFYB/sweyY7uxvviY/Phrph2azDVTNGDk7TZoBXpmdly3GdavdPGq8po03hPN2oy4yObWtaQnJuw2/4HXWsW6A0aKy9Qv76ShQKBgQD5vhWb2sYr6zBLi1MjUYu1dLuImo2m22NBfk1QPa8FsW/Z8MqSjJGIVtZHPVG1gpRl/tXyUAdaIcdnksLQwTQI1JVe5gaZZodxFSfs7azSP7ctHKCfRNSSqt2Ly62EiiyjUWsrL8o/UxwTQGHR4hJnGxqq2AGFNcFLLZRPGXtDtwKBgQDP7uUd3YWgovxc9apgofsdUoaNPqtE+gVAiic1GAz/6RPgTNqiQvv0RqukrUQa8F21xWsedEZH042Zi619J9OTEhZ+EbCKDqKShPH2b5qK1eMzIlECZO1kCqyrFdyzq2zMxhgfBC3S/ab1V/bgVxQaV8++uV+Snmu86DqzG7ID4wKBgF9sivMnL4s+bRCgZp7bHKezt6glbbRwpUc0DDR5rTNerd83Sx+dyEmw7GUCAAN7plomefcBLx34RCnGANwkxk4NdBlziNf6PgwuSjgURHF9WO9KvfC9Kv/ze31b0KwQ46dvh6RTuVJi3hpZAkdguylcSN84c7RDatzfyIhEsz2XAoGBAMJdAHXmN55sO5F5YYVqZByIo5Ur21RikL4/ZV7P2HbuG9IyhLvf+TvhQ1hvTZYQ0Me0fei9r2Q8b8PzOHwg2jhDVBsL1gV2oKhs9O/yancUb4fAsBCY3v4ArF5P1TltKApRsQJtGZh72bDERNR3ESd+pYYWKSwYQYUXXqdFYCUZAoGBALqPi0VfUymHsN91mK+73j8BDX+me1sYgGELHq06m3fc2zToJLhXfE2hwQRdWLcHFJVvI0TP20YLWONCcNt8OAudmCpdg85tRqV7Yndll4Hu+sj+RLX3nwIcEDgnzchXcZRtVQdbnWAVDLjq4vkj4CB01MioPnqhtfdPCA57JI4M\",\"publicKey\":\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAytnBtUjD9DmiQvc1RFGGRrvXdZq8/VlZtsF3f6FJv+SugDtGP99uG5tqVnoGkTBO6BWb8D3Ny0mPTUMo1+hthU+z2Wda//OgJOKe73kx7Jl5zPuxb+vFO0vWWuKqTFxLYoKiksAW+/l4yBIibWVU98HJbMS/1wsnumO9g7saJJpKSYfsgAcyGLpKLP/wYfCoddkNyDsXqyZbvxyRek5J0ju8UdQ7ZTwRTrsaOyWSrya2wAGdBpo0+VpKROxgXHOPjgzNBxT8QB4G7eXmae/oblhfgqGQgtHf9k2lT3/y773E6dQyo8XJWLroBBduEuRyKSnyt1Cgfp4pNvY+bFYwRQIDAQAB\"}",
	"apiKeys":            "{\"KeyManagementToken\":[\"tsb-x-token_689089e5f323b2f51390a7bf6960b03a9e3ca299ddf703666215d9a18ab37486\"],\"KeyOperationToken\":[\"tsb-x-token_03db3ef6e4670c593c7459ff1c9b6c7a64a227c81d6571269aea2cd8328361b2\"],\"ServiceToken\":[\"tsb-x-token_4be180a5640ad1969fac96c93f19fd4d565d387b66e700fb26a156ab9611ade7\"],\"ApproverToken\":[\"tsb-x-token_07f9f3e39a7ca91ab6f7694f6beef465d7b27d9ccaf293e33b15c3a939cda850\"]}",
}

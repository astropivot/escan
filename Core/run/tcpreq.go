package run

import (
	"errors"
	"escan/Common"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// WrapperTcpWithTimeout 创建一个带超时的TCP连接
func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return WrapperTCP(network, address, d)
}

// WrapperTCP 根据配置创建TCP连接
func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	// 直连模式
	if Common.Args.Socks5Proxy == "" {
		conn, err := forward.Dial(network, address)
		if err != nil {
			return nil, fmt.Errorf("tcp失败:%s", err)
		}
		return conn, nil
	}

	// Socks5代理模式
	dialer, err := Socks5Dialer(forward)
	if err != nil {
		return nil, fmt.Errorf("创建socks5代理失败:%s", err)
	}

	conn, err2 := dialer.Dial(network, address)
	if err2 != nil {
		return nil, fmt.Errorf("socks5连接失败:%s", err2)
	}

	return conn, nil
}

// Socks5Dialer 创建Socks5代理拨号器
func Socks5Dialer(forward *net.Dialer) (proxy.Dialer, error) {
	// 解析代理URL
	u, err := url.Parse(Common.Args.Socks5Proxy)
	if err != nil {
		return nil, fmt.Errorf("socks5解析失败:%s", err)
	}

	// 验证代理类型
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("仅能socks5协议")
	}

	address := u.Host
	var dialer proxy.Dialer

	// 根据认证信息创建代理
	if u.User.String() != "" {
		// 使用用户名密码认证
		auth := proxy.Auth{
			User: u.User.Username(),
		}
		auth.Password, _ = u.User.Password()
		dialer, err = proxy.SOCKS5("tcp", address, &auth, forward)
	} else {
		// 无认证模式
		dialer, err = proxy.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, fmt.Errorf("socks5代理创建失败:%s", err)
	}

	return dialer, nil
}

package Common

import (
	"errors"
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
	if Args.Socks5Proxy == "" {
		conn, err := forward.Dial(network, address)
		if err != nil {
			return nil, fmt.Errorf("tcp_conn_failed: %v", err)
		}
		return conn, nil
	}

	// Socks5代理模式
	dialer, err := Socks5Dialer(forward)
	if err != nil {
		return nil, fmt.Errorf("socks5_create_failed: %v", err)
	}

	conn, err := dialer.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("socks5_conn_failed: %v", err)
	}

	return conn, nil
}

// Socks5Dialer 创建Socks5代理拨号器
func Socks5Dialer(forward *net.Dialer) (proxy.Dialer, error) {
	// 解析代理URL
	u, err := url.Parse(Args.Socks5Proxy)
	if err != nil {
		return nil, fmt.Errorf("socks5_parse_failed: %v", err)
	}

	// 验证代理类型
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("socks5_only")
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
		return nil, fmt.Errorf("socks5_create_failed%v", err)
	}

	return dialer, nil
}

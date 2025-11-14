package plugintest

import (
	"testing"
)

// 这个文件提供了统一的测试入口
// 运行所有测试套件：go test -v
// 运行特定测试套件：go test -v -run TestSnatSuite

// TestMain 测试主入口（可选）
// 可以在这里添加全局的 setup 和 teardown 逻辑
func TestMain(m *testing.M) {
	// 全局初始化
	// log.SetLevel(log.DebugLevel)
	
	// 运行所有测试
	m.Run()
	
	// 全局清理
}

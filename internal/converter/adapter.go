package converter

// ConverterAdapter represents the interface for adapters that bridge between
// old and new converter implementations.
type ConverterAdapter interface {
	Converter
	SetOptions(opts interface{})
	GetOptions() interface{}
}

// Note: The actual MarkdownGeneratorAdapter has been moved to the markdown package
// to avoid import cycles. Use markdown.NewConverterAdapter() instead.

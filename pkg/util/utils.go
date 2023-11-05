package util

import "errors"

func Map[I, O any](in []I, f func(I) O) []O {
	list := make([]O, 0, len(in))
	for _, item := range in {
		list = append(list, f(item))
	}
	return list
}

func Filter[I any](in []I, f func(I) bool) []I {
	list := make([]I, 0, len(in))
	for _, item := range in {
		if f(item) {
			list = append(list, item)
		}
	}
	return list
}

func Has[I any](in []I, f func(I) bool) bool {
	for _, item := range in {
		if f(item) {
			return true
		}
	}
	return false
}

func MatchOne[I any](in []I, f func(I) bool) (*I, error) {
	var matched *I
	matchedOneAlready := false
	for i, item := range in {
		if f(item) {
			if matchedOneAlready {
				return nil, errors.New("need to match exactly one item")
			}
			matched = &in[i]
			matchedOneAlready = true
		}
	}
	if !matchedOneAlready {
		return nil, errors.New("need to match at least one")
	}
	return matched, nil
}

// TODO: what other generic things can we apply? is there lennable?
func FilterEmpty(in []string) []string {
	return Filter(in, func(s string) bool {
		return len(s) != 0
	})
}

func MapNonNil[I, O any](in []I, f func(I) *O) []O {
	list := make([]O, 0, len(in))
	for _, item := range in {
		out := f(item)
		if out != nil {
			list = append(list, *out)
		}
	}
	return list
}

func DereferenceList[T any](ptrlist []*T) []T {
	if ptrlist == nil {
		return nil
	}
	list := make([]T, 0, len(ptrlist))
	for _, ptr := range ptrlist {
		if ptr == nil {
			continue
		}
		list = append(list, *ptr)
	}
	return list
}

func FlatMap[I, O any](in []I, f func(I) []O) []O {
	list := make([]O, 0, len(in))
	for _, item := range in {
		list = append(list, f(item)...)
	}
	return list
}

func FlatMapWithError[I, O any](in []I, f func(I) ([]O, error)) ([]O, error) {
	list := make([]O, 0, len(in))
	for _, item := range in {
		sublist, err := f(item)
		if err != nil {
			return nil, err
		}
		list = append(list, sublist...)
	}
	return list, nil
}

func Must[T any](t T, err error) T {
	PanicIfError(err)
	return t
}

func PanicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

package result

import (
	"math/rand"
	"time"
)

type Rander struct {
	Arrays [][]string
	Out    chan []string
}

func Rand(arrays ...[]string) chan []string {
	out := make(chan []string)
	r := &Rander{
		Arrays: arrays,
		Out:    out,
	}
	go r.runArraysRand()
	return out
}

func (r *Rander) runArraysRand() {
	rand.Seed(time.Now().UnixNano())
	var combinations [][]string
	generateCombinations(r.Arrays, []string{}, &combinations)

	// 随机排序组合
	rand.Shuffle(len(combinations), func(i, j int) {
		combinations[i], combinations[j] = combinations[j], combinations[i]
	})

	for _, combination := range combinations {
		r.Out <- combination
	}
	close(r.Out)
}
func generateCombinations(arrays [][]string, currentCombination []string, combinations *[][]string) {
	if len(arrays) == 0 {
		*combinations = append(*combinations, currentCombination)
		return
	}

	for _, value := range arrays[0] {
		newCombination := append(currentCombination, value)
		generateCombinations(arrays[1:], newCombination, combinations)
	}
}

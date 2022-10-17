package Tokenbucket

import (
	"time"
)

// The TokenBucket struct that stores all the informations needed for the Token Bucket algorithm.
type TokenBucket struct {
	CIRInBytes        uint64
	CurrentTokens     float64
	LastPacketTime    time.Time
	TokenIntervalInMs uint64 //any value in [1,1000]
}

// A placeholder packet struct.
type TokenBucketEntry struct {
	Length      uint64
	ArrivalTime time.Time
}

// this function calculates the minimal value of two floats.
func min(a float64, b float64) float64 {
	if a > b {
		return b
	} else {
		return a
	}
}

// ValidateBandwidth checks whether a packet fits in the Token Bucket or drops it. The success is indicated by a bool.
func (bucket *TokenBucket) ValidateBandwidth(entry *TokenBucketEntry) bool {
	if bucket == nil || entry == nil {
		return false
	}
	//calculates the time difference between the last and the current packet
	//and subtracts the part that is not divisible by the token intervall.
	var currentTime time.Time = entry.ArrivalTime
	var timeDiff time.Duration = currentTime.Sub(bucket.LastPacketTime)
	timeDiff = timeDiff - time.Duration(timeDiff.Milliseconds()%int64(bucket.TokenIntervalInMs)*int64(time.Millisecond))

	//calculates the current amount of tokens given the calculated time difference
	bucket.CurrentTokens = min(float64(bucket.CIRInBytes), bucket.CurrentTokens+float64(bucket.CIRInBytes)*float64(timeDiff.Milliseconds())/1000)
	bucket.LastPacketTime = bucket.LastPacketTime.Add(timeDiff)

	if entry.Length <= uint64(bucket.CurrentTokens) {
		bucket.CurrentTokens -= float64(entry.Length)
		return true
	} else {
		return false
	}
}

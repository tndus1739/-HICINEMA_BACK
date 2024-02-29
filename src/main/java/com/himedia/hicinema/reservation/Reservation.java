package com.himedia.hicinema.reservation;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;

import com.himedia.hicinema.member.Member;

import groovy.transform.ToString;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name= "reservation")
@Data
@ToString
public class Reservation {

	@Id 
	@GeneratedValue(strategy = GenerationType.IDENTITY) 
	@Column(name="reservation_id")
    private long id;
	
	@ManyToOne
	@JoinColumn(name="member_id")
	private Member member;
	
	
	@Column
	private String ticket_movie;   // 예매한 영롸
	
	@Column
	private String theater_number; // 영화관
	
	@Column 
	private String movie_date;     // 상영날짜
	
	@Column
	private String seat_number;    // 좌석번호	
	@Column
	private String pay_number;	   // 결제번호
	
	@Column
	private String price;			// 금액
	

	private LocalDateTime ticket_regdate;
	
	private LocalDateTime ticket_delDate;

	private String status;   //상태 : 기본 : O , 미노출 :  X, 삭제 : D
	
 
	
	
	
	
}

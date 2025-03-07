/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// TicketDetailInfo
    /// </summary>
    [DataContract(Name = "TicketDetailInfo")]
    public partial class TicketDetailInfo : IEquatable<TicketDetailInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TicketDetailInfo" /> class.
        /// </summary>
        /// <param name="amount">总金额，元为单位.</param>
        /// <param name="endStation">终点站编码.</param>
        /// <param name="endStationName">终点站中文名称.</param>
        /// <param name="quantity">票数量.</param>
        /// <param name="startStation">起点站编码.</param>
        /// <param name="startStationName">起点站中文名称.</param>
        /// <param name="status">订单状态.</param>
        /// <param name="ticketPrice">单价，元为单位.</param>
        /// <param name="ticketType">票类型.</param>
        /// <param name="tradeNo">支付宝交易号.</param>
        public TicketDetailInfo(string amount = default(string), string endStation = default(string), string endStationName = default(string), string quantity = default(string), string startStation = default(string), string startStationName = default(string), string status = default(string), string ticketPrice = default(string), string ticketType = default(string), string tradeNo = default(string))
        {
            this.Amount = amount;
            this.EndStation = endStation;
            this.EndStationName = endStationName;
            this.Quantity = quantity;
            this.StartStation = startStation;
            this.StartStationName = startStationName;
            this.Status = status;
            this.TicketPrice = ticketPrice;
            this.TicketType = ticketType;
            this.TradeNo = tradeNo;
        }

        /// <summary>
        /// 总金额，元为单位
        /// </summary>
        /// <value>总金额，元为单位</value>
        [DataMember(Name = "amount", EmitDefaultValue = false)]
        public string Amount { get; set; }

        /// <summary>
        /// 终点站编码
        /// </summary>
        /// <value>终点站编码</value>
        [DataMember(Name = "end_station", EmitDefaultValue = false)]
        public string EndStation { get; set; }

        /// <summary>
        /// 终点站中文名称
        /// </summary>
        /// <value>终点站中文名称</value>
        [DataMember(Name = "end_station_name", EmitDefaultValue = false)]
        public string EndStationName { get; set; }

        /// <summary>
        /// 票数量
        /// </summary>
        /// <value>票数量</value>
        [DataMember(Name = "quantity", EmitDefaultValue = false)]
        public string Quantity { get; set; }

        /// <summary>
        /// 起点站编码
        /// </summary>
        /// <value>起点站编码</value>
        [DataMember(Name = "start_station", EmitDefaultValue = false)]
        public string StartStation { get; set; }

        /// <summary>
        /// 起点站中文名称
        /// </summary>
        /// <value>起点站中文名称</value>
        [DataMember(Name = "start_station_name", EmitDefaultValue = false)]
        public string StartStationName { get; set; }

        /// <summary>
        /// 订单状态
        /// </summary>
        /// <value>订单状态</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// 单价，元为单位
        /// </summary>
        /// <value>单价，元为单位</value>
        [DataMember(Name = "ticket_price", EmitDefaultValue = false)]
        public string TicketPrice { get; set; }

        /// <summary>
        /// 票类型
        /// </summary>
        /// <value>票类型</value>
        [DataMember(Name = "ticket_type", EmitDefaultValue = false)]
        public string TicketType { get; set; }

        /// <summary>
        /// 支付宝交易号
        /// </summary>
        /// <value>支付宝交易号</value>
        [DataMember(Name = "trade_no", EmitDefaultValue = false)]
        public string TradeNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class TicketDetailInfo {\n");
            sb.Append("  Amount: ").Append(Amount).Append("\n");
            sb.Append("  EndStation: ").Append(EndStation).Append("\n");
            sb.Append("  EndStationName: ").Append(EndStationName).Append("\n");
            sb.Append("  Quantity: ").Append(Quantity).Append("\n");
            sb.Append("  StartStation: ").Append(StartStation).Append("\n");
            sb.Append("  StartStationName: ").Append(StartStationName).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  TicketPrice: ").Append(TicketPrice).Append("\n");
            sb.Append("  TicketType: ").Append(TicketType).Append("\n");
            sb.Append("  TradeNo: ").Append(TradeNo).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as TicketDetailInfo);
        }

        /// <summary>
        /// Returns true if TicketDetailInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of TicketDetailInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TicketDetailInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Amount == input.Amount ||
                    (this.Amount != null &&
                    this.Amount.Equals(input.Amount))
                ) && 
                (
                    this.EndStation == input.EndStation ||
                    (this.EndStation != null &&
                    this.EndStation.Equals(input.EndStation))
                ) && 
                (
                    this.EndStationName == input.EndStationName ||
                    (this.EndStationName != null &&
                    this.EndStationName.Equals(input.EndStationName))
                ) && 
                (
                    this.Quantity == input.Quantity ||
                    (this.Quantity != null &&
                    this.Quantity.Equals(input.Quantity))
                ) && 
                (
                    this.StartStation == input.StartStation ||
                    (this.StartStation != null &&
                    this.StartStation.Equals(input.StartStation))
                ) && 
                (
                    this.StartStationName == input.StartStationName ||
                    (this.StartStationName != null &&
                    this.StartStationName.Equals(input.StartStationName))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
                ) && 
                (
                    this.TicketPrice == input.TicketPrice ||
                    (this.TicketPrice != null &&
                    this.TicketPrice.Equals(input.TicketPrice))
                ) && 
                (
                    this.TicketType == input.TicketType ||
                    (this.TicketType != null &&
                    this.TicketType.Equals(input.TicketType))
                ) && 
                (
                    this.TradeNo == input.TradeNo ||
                    (this.TradeNo != null &&
                    this.TradeNo.Equals(input.TradeNo))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.Amount != null)
                {
                    hashCode = (hashCode * 59) + this.Amount.GetHashCode();
                }
                if (this.EndStation != null)
                {
                    hashCode = (hashCode * 59) + this.EndStation.GetHashCode();
                }
                if (this.EndStationName != null)
                {
                    hashCode = (hashCode * 59) + this.EndStationName.GetHashCode();
                }
                if (this.Quantity != null)
                {
                    hashCode = (hashCode * 59) + this.Quantity.GetHashCode();
                }
                if (this.StartStation != null)
                {
                    hashCode = (hashCode * 59) + this.StartStation.GetHashCode();
                }
                if (this.StartStationName != null)
                {
                    hashCode = (hashCode * 59) + this.StartStationName.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                if (this.TicketPrice != null)
                {
                    hashCode = (hashCode * 59) + this.TicketPrice.GetHashCode();
                }
                if (this.TicketType != null)
                {
                    hashCode = (hashCode * 59) + this.TicketType.GetHashCode();
                }
                if (this.TradeNo != null)
                {
                    hashCode = (hashCode * 59) + this.TradeNo.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
